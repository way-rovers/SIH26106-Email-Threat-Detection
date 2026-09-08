"""geolocation/test_geolocation.py — shape-check tests for geolocate_ip()."""

import pytest
from unittest.mock import patch, MagicMock
import geolocation.main as geo_module
from geolocation.main import geolocate_ip, geolocate_batch

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


# --- Milestone 3.2 ---

def test_private_ip_short_circuits():
    """Private IPs must be rejected before any network call."""
    result = geolocate_ip("192.168.1.1")
    assert result["error"] == "private/reserved IP"
    assert result["country"] == "unknown"
    assert result["lat"] is None


def test_loopback_ip_short_circuits():
    result = geolocate_ip("127.0.0.1")
    assert result["error"] == "private/reserved IP"


def test_malformed_ip_short_circuits():
    """Non-IP strings must return cleanly without hitting the network."""
    result = geolocate_ip("not-an-ip")
    assert result["error"] == "invalid IP address"
    assert result["ip"] == "not-an-ip"
    assert REQUIRED_KEYS == result.keys()


# --- Milestone 3.3 ---

_FAKE_RESPONSE = {
    "status": "success", "country": "United States", "city": "Ashburn",
    "isp": "Google LLC", "lat": 39.03, "lon": -77.5, "query": "8.8.8.8",
}


@pytest.fixture(autouse=False)
def reset_cache(tmp_path):
    """Clear in-memory cache and redirect disk cache to a temp file per test."""
    import geolocation.main as _m
    orig_path = _m._CACHE_PATH
    _m._CACHE_PATH = tmp_path / "geo_cache_test.json"  # empty, doesn't exist
    _m._cache.clear()
    _m._cache_ready = False
    yield
    _m._cache.clear()
    _m._cache_ready = False
    _m._CACHE_PATH = orig_path



def test_cache_hit_avoids_second_network_call(reset_cache):
    """Calling geolocate_ip() twice for the same IP must hit the network once."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = _FAKE_RESPONSE
    mock_resp.raise_for_status.return_value = None

    with patch("geolocation.main.requests.get", return_value=mock_resp) as mock_get, \
         patch("geolocation.main._flush_cache"):          # don't touch disk
        first  = geolocate_ip("8.8.8.8")
        second = geolocate_ip("8.8.8.8")

    assert mock_get.call_count == 1, (
        f"Expected 1 network call, got {mock_get.call_count}"
    )
    assert first == second
    assert first["error"] == ""


def test_cache_returns_full_contract_shape(reset_cache):
    """A cache hit must still return all required keys."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = _FAKE_RESPONSE
    mock_resp.raise_for_status.return_value = None

    with patch("geolocation.main.requests.get", return_value=mock_resp), \
         patch("geolocation.main._flush_cache"):
        geolocate_ip("8.8.8.8")          # populates cache
        result = geolocate_ip("8.8.8.8") # cache hit

    assert REQUIRED_KEYS == result.keys()


def test_geolocate_batch_mixed_inputs(reset_cache):
    """Batch with public + private + malformed IPs returns correct shapes."""
    _FAKE_BATCH = [
        {"status": "success", "country": "US", "city": "Ashburn",
         "isp": "Google LLC", "lat": 39.03, "lon": -77.5, "query": "8.8.8.8"},
        {"status": "success", "country": "DE", "city": "Frankfurt",
         "isp": "Cloudflare", "lat": 50.11, "lon": 8.68, "query": "1.1.1.1"},
    ]
    mock_resp = MagicMock()
    mock_resp.json.return_value = _FAKE_BATCH
    mock_resp.raise_for_status.return_value = None

    ips = ["8.8.8.8", "192.168.1.1", "not-an-ip", "1.1.1.1"]
    with patch("geolocation.main.requests.post", return_value=mock_resp), \
         patch("geolocation.main._flush_cache"):
        results = geolocate_batch(ips)

    assert len(results) == 4
    assert results[0]["ip"] == "8.8.8.8"   and results[0]["error"] == ""
    assert results[1]["error"] == "private/reserved IP"
    assert results[2]["error"] == "invalid IP address"
    assert results[3]["ip"] == "1.1.1.1"   and results[3]["error"] == ""


def test_geolocate_batch_no_network_for_all_private(reset_cache):
    """Batch of only private/malformed IPs must not hit the network at all."""
    with patch("geolocation.main.requests.post") as mock_post:
        results = geolocate_batch(["10.0.0.1", "172.16.0.1", "bad"])

    mock_post.assert_not_called()
    assert all(r["error"] != "" for r in results)


# ---------------------------------------------------------------------------
# Milestone 3.5 — Real cross-module integration against forensics fixtures
# ---------------------------------------------------------------------------

import pathlib
import time

from forensics.main import parse_email

_FIXTURES_DIR = pathlib.Path(__file__).resolve().parent.parent / "contracts" / "fixtures"
_FIXTURES = sorted(_FIXTURES_DIR.glob("*.eml"))


@pytest.mark.parametrize("eml_path", _FIXTURES, ids=[f.name for f in _FIXTURES])
def test_integration_fixture_hop_shape(eml_path):
    """Every geolocate_ip() result for a real fixture hop has the correct shape."""
    parsed = parse_email(str(eml_path))
    chain  = parsed.get("received_chain", [])

    # Fixtures with no Received headers are valid — nothing to geolocate.
    routable_hops = [h for h in chain if h.get("ip")]

    for hop in routable_hops:
        ip     = hop["ip"]
        result = geolocate_ip(ip)

        assert isinstance(result, dict), \
            f"geolocate_ip({ip!r}) must return a dict"
        missing = REQUIRED_KEYS - result.keys()
        assert not missing, \
            f"geolocate_ip({ip!r}) missing keys: {missing}"
        assert result["ip"] == ip, \
            f"ip field mismatch: expected {ip!r}, got {result['ip']!r}"

        if result["error"] == "":
            assert isinstance(result["lat"], (int, float)), \
                f"lat not numeric for {ip!r}"
            assert isinstance(result["lon"], (int, float)), \
                f"lon not numeric for {ip!r}"


def test_integration_batch_all_fixtures_fast():
    """Batch lookup across all fixtures is cache-fast and correctly shaped.

    Collects every unique public IP from every fixture, calls geolocate_batch
    once, and asserts all results have the required contract shape and that
    the full round-trip completes in under 5 seconds (cache hit or single
    batch POST — never multiple sequential single requests).
    """
    seen: set[str] = set()
    ip_list: list[str] = []
    for eml_path in _FIXTURES:
        parsed = parse_email(str(eml_path))
        for hop in parsed.get("received_chain", []):
            ip = hop.get("ip", "")
            if ip and ip not in seen:
                seen.add(ip)
                ip_list.append(ip)

    if not ip_list:
        pytest.skip("No routable IPs found in any fixture.")

    t0      = time.monotonic()
    results = geolocate_batch(ip_list)
    elapsed = time.monotonic() - t0

    assert len(results) == len(ip_list), \
        "geolocate_batch must return one result per input IP"

    for ip, result in zip(ip_list, results):
        missing = REQUIRED_KEYS - result.keys()
        assert not missing, \
            f"geolocate_batch result for {ip!r} missing keys: {missing}"

    # Cached lookups should be milliseconds; a live batch POST < 2 s.
    # 5 s is a generous ceiling that catches the pathological case of
    # sequential single requests firing for every hop.
    assert elapsed < 5.0, (
        f"Batch lookup took {elapsed:.2f}s — expected cache hit or single POST."
    )
