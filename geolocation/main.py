"""
geolocation/main.py — Person 6: IP geolocation + relay-path mapping.

Public contract:
    geolocate_ip(ip: str) -> dict

Return shape:
{
    "ip":      str,
    "country": str,
    "city":    str,
    "isp":     str,
    "lat":     float | None,
    "lon":     float | None,
    "error":   str | None,   # None on success, error message on failure
}

Rules:
- Never raise an exception — set error field instead.
- Cache results (dict + persistent JSON) to avoid hitting rate limits during demos.
- Filter private, reserved, and loopback IPs without calling the external API.
- Called once per hop in parsed["received_chain"] that has a non-null ip.
"""

import json
import logging
import os
from pathlib import Path
import ipaddress
import requests

logger = logging.getLogger(__name__)

# Primary API endpoint (free tier, 45 requests/minute, no API key required)
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,lat,lon,query"
REQUEST_TIMEOUT_SECONDS = 2.5

# Disk cache file location (relative to repo root)
CACHE_DIR = Path(__file__).resolve().parent.parent / "data"
CACHE_FILE = CACHE_DIR / "geo_cache.json"

# In-memory cache
_GEO_CACHE: dict[str, dict] = {}


def _load_disk_cache() -> None:
    """Load cached geolocation records from disk if available."""
    global _GEO_CACHE
    if not CACHE_FILE.exists():
        return
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                _GEO_CACHE.update(data)
    except Exception as exc:
        logger.warning("Failed to load geo cache from disk: %s", exc)


def _save_to_disk_cache(ip: str, record: dict) -> None:
    """Save a single record to the disk cache file."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        # Re-read existing or use in-memory to prevent overwriting
        disk_data = {}
        if CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    disk_data = json.load(f)
            except Exception:
                disk_data = {}
        disk_data[ip] = record
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(disk_data, f, indent=2)
    except Exception as exc:
        logger.warning("Failed to persist geo cache to disk: %s", exc)


# Initialize disk cache on module import
_load_disk_cache()


def _validate_ip(raw_ip: str) -> tuple[str, str | None]:
    """Validate raw IP string and check for non-public ranges.

    Returns:
        (clean_ip, non_public_reason)
        If valid public IP, non_public_reason is None.
        If invalid or non-public, non_public_reason contains a description.
    """
    if not isinstance(raw_ip, str):
        return str(raw_ip), "Input must be a string"

    clean_ip = raw_ip.strip(" []")
    if not clean_ip:
        return "", "Empty IP address"

    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return clean_ip, f"Invalid IP address format: '{clean_ip}'"

    if ip_obj.is_loopback:
        return clean_ip, "Loopback IP address"
    if ip_obj.is_private:
        return clean_ip, "Private network IP (RFC 1918)"
    if ip_obj.is_reserved:
        return clean_ip, "Reserved IP range"
    if ip_obj.is_multicast:
        return clean_ip, "Multicast IP range"
    if ip_obj.is_link_local:
        return clean_ip, "Link-local IP address"
    if ip_obj.is_unspecified:
        return clean_ip, "Unspecified IP address"

    return clean_ip, None


def geolocate_ip(ip: str) -> dict:
    """Look up geolocation data for *ip*.

    Strict Contract Compliance:
    - Never raises an exception under any failure condition.
    - Local cache avoids hitting rate limits during demos.
    - Checks RFC 1918/reserved addresses without external network calls.

    Args:
        ip: An IPv4 or IPv6 address string.

    Returns:
        A dict with keys: ip, country, city, isp, lat, lon, error.
    """
    clean_ip, non_public_error = _validate_ip(ip)

    # Handle invalid or non-public IP (skip external API)
    if non_public_error:
        return {
            "ip": clean_ip if clean_ip else (ip if isinstance(ip, str) else ""),
            "country": "unknown",
            "city": "unknown",
            "isp": "unknown",
            "lat": None,
            "lon": None,
            "error": non_public_error,
        }

    # Check in-memory cache first
    if clean_ip in _GEO_CACHE:
        return dict(_GEO_CACHE[clean_ip])

    # Call external API
    try:
        url = IP_API_URL.format(ip=clean_ip)
        resp = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)

        if resp.status_code == 429:
            return {
                "ip": clean_ip,
                "country": "unknown",
                "city": "unknown",
                "isp": "unknown",
                "lat": None,
                "lon": None,
                "error": "API rate limit exceeded (HTTP 429)",
            }

        resp.raise_for_status()
        data = resp.json()

        if data.get("status") == "success":
            record = {
                "ip": clean_ip,
                "country": data.get("country") or "unknown",
                "city": data.get("city") or "unknown",
                "isp": data.get("isp") or "unknown",
                "lat": float(data["lat"]) if data.get("lat") is not None else None,
                "lon": float(data["lon"]) if data.get("lon") is not None else None,
                "error": None,
            }
            # Cache successfully resolved public IP
            _GEO_CACHE[clean_ip] = record
            _save_to_disk_cache(clean_ip, record)
            return dict(record)

        # Status was "fail" according to ip-api
        fail_msg = data.get("message", "Lookup failed")
        return {
            "ip": clean_ip,
            "country": "unknown",
            "city": "unknown",
            "isp": "unknown",
            "lat": None,
            "lon": None,
            "error": f"API error: {fail_msg}",
        }

    except requests.exceptions.Timeout:
        return {
            "ip": clean_ip,
            "country": "unknown",
            "city": "unknown",
            "isp": "unknown",
            "lat": None,
            "lon": None,
            "error": f"API request timed out ({REQUEST_TIMEOUT_SECONDS}s)",
        }
    except requests.exceptions.RequestException as exc:
        return {
            "ip": clean_ip,
            "country": "unknown",
            "city": "unknown",
            "isp": "unknown",
            "lat": None,
            "lon": None,
            "error": f"Network error: {exc.__class__.__name__}",
        }
    except Exception as exc:
        # Ultimate fallback — NEVER raise an exception
        return {
            "ip": clean_ip,
            "country": "unknown",
            "city": "unknown",
            "isp": "unknown",
            "lat": None,
            "lon": None,
            "error": f"Unexpected error: {str(exc)}",
        }


def clear_cache() -> None:
    """Clear in-memory and disk cache (useful for testing)."""
    global _GEO_CACHE
    _GEO_CACHE.clear()
    if CACHE_FILE.exists():
        try:
            CACHE_FILE.unlink()
        except Exception:
            pass


def get_cache_stats() -> dict:
    """Return diagnostic cache statistics."""
    return {
        "cached_ips_count": len(_GEO_CACHE),
        "disk_cache_exists": CACHE_FILE.exists(),
        "disk_cache_path": str(CACHE_FILE),
    }
