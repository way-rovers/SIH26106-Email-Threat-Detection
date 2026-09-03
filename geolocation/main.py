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
    "error":   str | None,   # null on success, error message on failure
}

Rules:
- Never raise an exception — set error field instead.
- Cache results (dict or SQLite) to avoid hitting rate limits during demos.
- Called once per hop in parsed["received_chain"] that has a non-null ip.
"""


def geolocate_ip(ip: str) -> dict:
    """Look up geolocation data for *ip*.

    STUB — currently returns hardcoded example data. Replace with a real
    ip-api.com / ipinfo.io call (with caching!) in Phase 1.

    Args:
        ip: An IPv4 or IPv6 address string.

    Returns:
        A dict with keys: ip, country, city, isp, lat, lon, error.
    """
    # HARDCODED STUB — replace with real API call + cache in Phase 1.
    return {
        "ip": ip,
        "country": "Russia",
        "city": "Moscow",
        "isp": "Tor Exit Node / Hosting AS12345",
        "lat": 55.7558,
        "lon": 37.6173,
        "error": None,
    }
