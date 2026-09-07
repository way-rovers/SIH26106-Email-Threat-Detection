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
import folium

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


def _hop_role(position: int, total_hops: int) -> str:
    """Classify a hop's position in the relay chain.

    Returns one of "origin", "destination", "intermediate" based on where
    it sits in the *full* received_chain (not just the hops with valid
    coordinates) so that "hop 0" and "the last hop" retain their meaning
    even when some hops in between get dropped for missing coordinates.
    """
    if total_hops <= 1:
        return "origin"
    if position == 0:
        return "origin"
    if position == total_hops - 1:
        return "destination"
    return "intermediate"


_ROLE_STYLE = {
    "origin": {"color": "red", "icon": "flag", "label": "Origin (earliest hop)"},
    "destination": {"color": "green", "icon": "envelope", "label": "Destination MX"},
    "intermediate": {"color": "orange", "icon": "arrow-right", "label": "Transit relay"},
}


def _hop_popup_html(position: int, hop: dict, role: str) -> str:
    """Build a small HTML popup body for a single hop marker."""
    ip = hop.get("ip", "unknown")
    city = hop.get("city") or "unknown"
    country = hop.get("country") or "unknown"
    isp = hop.get("isp") or "unknown"
    error = hop.get("error")
    status = "Resolved" if not error else f"Unresolved ({error})"
    role_label = _ROLE_STYLE.get(role, {}).get("label", role)

    return (
        f"<div style='font-family: sans-serif; font-size: 13px; min-width: 180px'>"
        f"<b>Hop #{position}</b> &mdash; {role_label}<br>"
        f"<b>IP:</b> {ip}<br>"
        f"<b>Location:</b> {city}, {country}<br>"
        f"<b>ISP/ASN:</b> {isp}<br>"
        f"<b>Status:</b> {status}"
        f"</div>"
    )


def _empty_relay_map(note: str) -> "folium.Map":
    """Return a clean neutral world map annotated with *note*.

    Used when geo_hops is empty or none of the hops resolved to valid
    coordinates, so the dashboard never breaks even on fully-private or
    fully-failed relay chains. The note is rendered as a fixed HTML overlay
    (not a folium.Marker) so callers counting relay-hop markers on the map
    see zero, as expected for a chain with no plottable hops.
    """
    fmap = folium.Map(location=[20.0, 0.0], zoom_start=2, tiles="OpenStreetMap")
    note_html = (
        "<div style='position: fixed; top: 12px; left: 50%; transform: translateX(-50%); "
        "z-index: 9999; background: white; padding: 8px 14px; border-radius: 6px; "
        "border: 1px solid #999; font-family: sans-serif; font-size: 13px; "
        f"color: #333; text-align: center; max-width: 80%;'>{note}</div>"
    )
    fmap.get_root().html.add_child(folium.Element(note_html))
    return fmap


def build_relay_map(geo_hops: list[dict]) -> "folium.Map":
    """Render an interactive relay-path map from a list of geolocate_ip() outputs.

    Args:
        geo_hops: ordered list of dicts, each shaped like geolocate_ip()'s
            return value, one per hop in the email's received_chain
            (earliest hop first, destination MX last). Hops with
            lat/lon == None (private/reserved/unresolved IPs) are skipped
            for markers and path-drawing but don't break rendering.

    Returns:
        A folium.Map. Never raises — always returns a renderable map, even
        for an empty list or a chain where every hop failed to resolve.
    """
    if not geo_hops:
        return _empty_relay_map("No relay hops available for this email.")

    total_hops = len(geo_hops)
    valid_points = []   # [(lat, lon), ...] in chain order, for the path + bounds
    any_valid = False

    fmap = folium.Map(location=[20.0, 0.0], zoom_start=2, tiles="OpenStreetMap")

    for position, hop in enumerate(geo_hops):
        hop = hop or {}
        lat = hop.get("lat")
        lon = hop.get("lon")

        if lat is None or lon is None:
            # Private/internal/unresolved hop — no marker, no path point.
            continue

        try:
            lat_f, lon_f = float(lat), float(lon)
        except (TypeError, ValueError):
            continue

        any_valid = True
        role = _hop_role(position, total_hops)
        style = _ROLE_STYLE[role]

        folium.Marker(
            location=[lat_f, lon_f],
            popup=folium.Popup(_hop_popup_html(position, hop, role), max_width=260),
            tooltip=f"Hop #{position} — {hop.get('city', 'unknown')}, {hop.get('country', 'unknown')}",
            icon=folium.Icon(color=style["color"], icon=style["icon"], prefix="fa"),
        ).add_to(fmap)

        valid_points.append((lat_f, lon_f))

    if not any_valid:
        return _empty_relay_map(
            "None of this email's relay hops had a resolvable public IP "
            "(private/internal addresses only, or all lookups failed)."
        )

    # Trajectory line across whichever valid hops we have, in chain order.
    if len(valid_points) >= 2:
        folium.PolyLine(
            locations=valid_points,
            color="#1f77b4",
            weight=3,
            opacity=0.75,
            dash_array="8, 6",
        ).add_to(fmap)

    # Auto-fit to the hops we actually plotted.
    if len(valid_points) == 1:
        fmap.location = valid_points[0]
        fmap.zoom_start = 6
    else:
        fmap.fit_bounds(valid_points)

    return fmap


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