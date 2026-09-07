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
    "lat":     float,
    "lon":     float,
    "error":   str,   # "" on success, error message on failure
}

Rules:
- Never raise an exception — set error field instead.
- Milestone 3.1: single real API call, no caching or private-IP handling yet.
"""

import requests

_API_BASE = "http://ip-api.com/json"
_TIMEOUT = 10  # seconds


def geolocate_ip(ip: str) -> dict:
    """Look up geolocation data for *ip* via ip-api.com.

    Args:
        ip: An IPv4 or IPv6 address string.

    Returns:
        A dict with keys: ip, country, city, isp, lat, lon, error.
        On success ``error`` is ``""``. On any failure ``error`` contains
        a human-readable message and the remaining fields are ``"unknown"``
        / ``None``.
    """
    _error_shape = {
        "ip": ip,
        "country": "unknown",
        "city": "unknown",
        "isp": "unknown",
        "lat": None,
        "lon": None,
    }

    try:
        response = requests.get(f"{_API_BASE}/{ip}", timeout=_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        return {**_error_shape, "error": "request timed out"}
    except requests.exceptions.RequestException as exc:
        return {**_error_shape, "error": f"network error: {exc}"}
    except ValueError as exc:
        return {**_error_shape, "error": f"invalid JSON response: {exc}"}

    if data.get("status") != "success":
        message = data.get("message", "lookup failed")
        return {**_error_shape, "error": f"ip-api error: {message}"}

    return {
        "ip": ip,
        "country": data.get("country", "unknown"),
        "city": data.get("city", "unknown"),
        "isp": data.get("isp", "unknown"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
        "error": "",
    }

