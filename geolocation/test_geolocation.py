"""geolocation/test_geolocation.py — shape-check tests for geolocate_ip()."""

import pytest
from geolocation.main import geolocate_ip

REQUIRED_KEYS = {"ip", "country", "city", "isp", "lat", "lon", "error"}


def test_geolocate_ip_returns_dict():
    result = geolocate_ip("185.220.101.45")
    assert isinstance(result, dict), "geolocate_ip() must return a dict"


def test_geolocate_ip_has_required_keys():
    result = geolocate_ip("185.220.101.45")
    missing = REQUIRED_KEYS - result.keys()
    assert not missing, f"geolocate_ip() is missing keys: {missing}"


def test_geolocate_ip_lat_lon_are_numeric():
    result = geolocate_ip("185.220.101.45")
    assert isinstance(result["lat"], (int, float)), "lat must be numeric"
    assert isinstance(result["lon"], (int, float)), "lon must be numeric"


def test_geolocate_ip_echoes_input():
    ip = "8.8.8.8"
    result = geolocate_ip(ip)
    assert result["ip"] == ip, "ip field must echo back the input"
