"""
geolocation/test_geolocation.py — Comprehensive tests for geolocate_ip().

Covers:
- Contract shape & key checks
- Public IP resolution & lat/lon types
- Private / Loopback / Reserved IP detection without API calls
- Bracketed IP stripping (e.g. from Received headers: "[1.2.3.4]")
- Malformed / empty / non-string IP safety
- Two-tier caching consistency
- Network failure & timeout resilience (zero exception guarantee)
"""

from unittest.mock import patch
import pytest
import requests
from geolocation.main import geolocate_ip, get_cache_stats

REQUIRED_KEYS = {"ip", "country", "city", "isp", "lat", "lon", "error"}


def test_geolocate_ip_returns_dict():
    result = geolocate_ip("8.8.8.8")
    assert isinstance(result, dict), "geolocate_ip() must return a dict"


def test_geolocate_ip_has_required_keys():
    result = geolocate_ip("8.8.8.8")
    missing = REQUIRED_KEYS - result.keys()
    assert not missing, f"geolocate_ip() is missing keys: {missing}"


def test_geolocate_ip_public_ip_success():
    result = geolocate_ip("8.8.8.8")
    assert result["ip"] == "8.8.8.8"
    if result["error"] is None:
        assert isinstance(result["lat"], (int, float))
        assert isinstance(result["lon"], (int, float))
        assert result["country"] != "unknown"


def test_geolocate_ip_bracketed_ip_stripping():
    result = geolocate_ip("[8.8.8.8]")
    assert result["ip"] == "8.8.8.8"


def test_geolocate_ip_private_rfc1918():
    for private_ip in ["10.0.0.1", "172.16.0.1", "192.168.1.100"]:
        result = geolocate_ip(private_ip)
        assert result["ip"] == private_ip
        assert result["country"] == "unknown"
        assert result["city"] == "unknown"
        assert result["lat"] is None
        assert result["lon"] is None
        assert "private" in result["error"].lower()


def test_geolocate_ip_loopback():
    result = geolocate_ip("127.0.0.1")
    assert result["ip"] == "127.0.0.1"
    assert result["country"] == "unknown"
    assert result["lat"] is None
    assert result["lon"] is None
    assert "loopback" in result["error"].lower()


def test_geolocate_ip_malformed_string():
    for bad_ip in ["not-an-ip", "999.999.999.999", "", "   "]:
        result = geolocate_ip(bad_ip)
        assert isinstance(result, dict)
        assert result["country"] == "unknown"
        assert result["lat"] is None
        assert result["lon"] is None
        assert result["error"] is not None


def test_geolocate_ip_non_string_input():
    result = geolocate_ip(None)
    assert isinstance(result, dict)
    assert result["error"] is not None
    assert result["lat"] is None


def test_geolocate_ip_caching_behavior():
    # Prime cache
    ip = "1.1.1.1"
    res1 = geolocate_ip(ip)
    # Second call should be served from cache
    res2 = geolocate_ip(ip)
    assert res1 == res2
    stats = get_cache_stats()
    assert stats["cached_ips_count"] >= 1


def test_geolocate_ip_simulated_network_timeout():
    with patch("requests.get", side_effect=requests.exceptions.Timeout("Timeout")):
        result = geolocate_ip("93.184.216.34")  # example.com IP
        assert isinstance(result, dict)
        assert result["country"] == "unknown"
        assert result["lat"] is None
        assert "timed out" in result["error"].lower()


def test_geolocate_ip_simulated_network_error():
    with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Offline")):
        result = geolocate_ip("93.184.216.35")
        assert isinstance(result, dict)
        assert result["country"] == "unknown"
        assert result["lat"] is None
        assert "network error" in result["error"].lower()
