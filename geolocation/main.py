"""
geolocation/main.py — Person 6: IP geolocation + relay-path mapping.

Public contract:
    geolocate_ip(ip: str) -> dict
    geolocate_batch(ips: list[str]) -> list[dict]

Return shape (per IP):
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
- Milestone 3.3: persistent JSON cache + batch endpoint for multi-IP lookups.
"""

import ipaddress
import json
import pathlib
import threading

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_API_SINGLE = "http://ip-api.com/json"
_API_BATCH  = "http://ip-api.com/batch"
_TIMEOUT    = 10  # seconds

# Cache lives at <project_root>/data/geo_cache.json regardless of cwd.
_CACHE_PATH: pathlib.Path = (
    pathlib.Path(__file__).resolve().parent.parent / "data" / "geo_cache.json"
)

# ---------------------------------------------------------------------------
# In-memory cache + persistence helpers
# ---------------------------------------------------------------------------

_cache: dict[str, dict] = {}
_cache_lock  = threading.Lock()
_cache_ready = False  # has the JSON file been loaded yet?


def _load_cache() -> None:
    """Populate *_cache* from disk (called once, inside the lock)."""
    global _cache_ready
    if _cache_ready:
        return
    if _CACHE_PATH.exists():
        try:
            with _CACHE_PATH.open() as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                _cache.update(data)
        except (json.JSONDecodeError, OSError):
            pass  # corrupt or missing — start empty, non-fatal
    _cache_ready = True


def _flush_cache() -> None:
    """Write *_cache* to disk (called inside the lock, failures are silent)."""
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _CACHE_PATH.open("w") as fh:
            json.dump(_cache, fh, indent=2)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_error(ip: str, message: str) -> dict:
    return {
        "ip":      ip,
        "country": "unknown",
        "city":    "unknown",
        "isp":     "unknown",
        "lat":     None,
        "lon":     None,
        "error":   message,
    }


def _validate(ip: str):
    """Return (addr, None) for routable IPs, or (None, error_dict) otherwise."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, _make_error(ip, "invalid IP address")
    if addr.is_private:
        return None, _make_error(ip, "private/reserved IP")
    return addr, None


def _parse_api_record(ip: str, data: dict) -> dict:
    """Turn a raw ip-api.com response dict into the contract shape."""
    if data.get("status") != "success":
        return _make_error(ip, f"ip-api error: {data.get('message', 'lookup failed')}")
    return {
        "ip":      ip,
        "country": data.get("country", "unknown"),
        "city":    data.get("city",    "unknown"),
        "isp":     data.get("isp",     "unknown"),
        "lat":     data.get("lat"),
        "lon":     data.get("lon"),
        "error":   "",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def geolocate_ip(ip: str) -> dict:
    """Look up geolocation data for *ip* via ip-api.com.

    Results are cached persistently in ``data/geo_cache.json``; a repeated
    call for the same IP incurs no additional network request.

    Args:
        ip: An IPv4 or IPv6 address string.

    Returns:
        A dict with keys: ip, country, city, isp, lat, lon, error.
        ``error`` is ``""`` on success; a human-readable string on failure.
    """
    # 3.2 guard — validate before any I/O
    _, err = _validate(ip)
    if err is not None:
        return err

    # 3.3 — cache lookup
    with _cache_lock:
        _load_cache()
        if ip in _cache:
            return _cache[ip]

    # Live API call
    try:
        response = requests.get(f"{_API_SINGLE}/{ip}", timeout=_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        return _make_error(ip, "request timed out")
    except requests.exceptions.RequestException as exc:
        return _make_error(ip, f"network error: {exc}")
    except ValueError as exc:
        return _make_error(ip, f"invalid JSON response: {exc}")

    result = _parse_api_record(ip, data)

    # Persist only successful lookups
    if result["error"] == "":
        with _cache_lock:
            _cache[ip] = result
            _flush_cache()

    return result


def geolocate_batch(ips: list[str]) -> list[dict]:
    """Geolocate multiple IPs in as few network calls as possible.

    Private/malformed IPs are handled locally; already-cached IPs are returned
    from memory; the remainder are sent together to ``ip-api.com/batch`` in a
    single POST (up to 100 IPs per call).

    Args:
        ips: List of IP address strings.

    Returns:
        List of contract-shape dicts in the same order as *ips*.
    """
    results: list[dict | None] = [None] * len(ips)
    to_fetch: list[tuple[int, str]] = []  # (original_index, ip)

    with _cache_lock:
        _load_cache()
        cache_snapshot = dict(_cache)

    for i, ip in enumerate(ips):
        _, err = _validate(ip)
        if err is not None:
            results[i] = err
            continue
        if ip in cache_snapshot:
            results[i] = cache_snapshot[ip]
            continue
        to_fetch.append((i, ip))

    if not to_fetch:
        return results  # type: ignore[return-value]

    # Batch POST — send up to 100 IPs at a time (free-tier limit)
    batch_ips = [ip for _, ip in to_fetch]
    try:
        response = requests.post(_API_BATCH, json=batch_ips, timeout=_TIMEOUT)
        response.raise_for_status()
        batch_data: list[dict] = response.json()
    except requests.exceptions.Timeout:
        for i, ip in to_fetch:
            results[i] = _make_error(ip, "request timed out")
        return results  # type: ignore[return-value]
    except requests.exceptions.RequestException as exc:
        for i, ip in to_fetch:
            results[i] = _make_error(ip, f"network error: {exc}")
        return results  # type: ignore[return-value]
    except ValueError as exc:
        for i, ip in to_fetch:
            results[i] = _make_error(ip, f"invalid JSON response: {exc}")
        return results  # type: ignore[return-value]

    new_entries: dict[str, dict] = {}
    for (i, ip), data in zip(to_fetch, batch_data):
        result = _parse_api_record(ip, data)
        results[i] = result
        if result["error"] == "":
            new_entries[ip] = result

    if new_entries:
        with _cache_lock:
            _cache.update(new_entries)
            _flush_cache()

    return results  # type: ignore[return-value]


