#!/usr/bin/env python3
"""
geolocation/map_test.py — Milestone 3.4: standalone relay-path map.

NOT part of the public contract. Run directly to generate an HTML map:

    python geolocation/map_test.py

Produces  geolocation/relay_path_map.html  and opens it in the default
browser so you can confirm the path looks like a real relay chain.
"""

import os
import pathlib
import sys
import webbrowser

import folium
from dotenv import load_dotenv
from folium.plugins import AntPath

# ---------------------------------------------------------------------------
# Add project root to path so geolocation package is importable when this
# script is run directly from any cwd.
# ---------------------------------------------------------------------------
_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))

# Load secrets from <project_root>/.env (silently a no-op if the file is absent).
load_dotenv(_ROOT / ".env")

from geolocation.main import geolocate_batch  # noqa: E402

# ---------------------------------------------------------------------------
# Tile layer — use CARTO dark_matter when a key is available, otherwise fall
# back to OpenStreetMap so the script works for teammates without a key.
# ---------------------------------------------------------------------------
_CARTO_KEY = os.getenv("CARTO_API_KEY", "").strip()

# ---------------------------------------------------------------------------
# Sample relay-chain IPs spanning multiple countries.
# These represent a plausible email header path:
#   India (origin MTA) → Singapore → USA (Google) → Germany (Tor exit) → destination
# ---------------------------------------------------------------------------
RELAY_IPS = [
    "203.88.139.115",   # India — origin MTA
    "103.86.96.100",    # Singapore — regional relay
    "8.8.8.8",          # United States — Google infrastructure
    "185.220.101.45",   # Germany — Tor exit node
]

# Marker colours keyed by hop role
_COLOUR = {
    "origin":       "#e74c3c",   # red
    "intermediate": "#3498db",   # blue
    "destination":  "#2ecc71",   # green
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hop_role(index: int, total: int) -> str:
    if index == 0:
        return "origin"
    if index == total - 1:
        return "destination"
    return "intermediate"


def _popup_html(hop: dict, role: str, index: int) -> str:
    colour = _COLOUR[role]
    label  = role.capitalize()
    return f"""
    <div style="font-family: sans-serif; min-width: 180px;">
        <b style="color:{colour};">#{index + 1} — {label}</b><br>
        <hr style="margin: 4px 0;">
        <b>IP:</b> {hop['ip']}<br>
        <b>Country:</b> {hop['country']}<br>
        <b>City:</b> {hop['city']}<br>
        <b>ISP:</b> {hop['isp']}<br>
        <small style="color:#888;">lat {hop['lat']:.4f}, lon {hop['lon']:.4f}</small>
    </div>
    """


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_map(ips: list[str]) -> folium.Map:
    """Geolocate *ips* and return a folium Map tracing the relay path."""
    print(f"[map_test] Geolocating {len(ips)} IPs …")
    results = geolocate_batch(ips)

    # Filter to hops with valid coordinates; warn on failures.
    hops = []
    for r in results:
        if r["error"]:
            print(f"  [SKIP] {r['ip']} — {r['error']}")
            continue
        hops.append(r)
        print(f"  [OK]   {r['ip']:20s}  {r['city']}, {r['country']}")

    if len(hops) < 2:
        raise RuntimeError(
            f"Need at least 2 routable hops to draw a path; got {len(hops)}."
        )

    coords = [(h["lat"], h["lon"]) for h in hops]

    # 1. Blank map — tiles added separately so no_wrap is respected.
    #    location/zoom are overridden by fit_bounds() at the end.
    m = folium.Map(
        location=[0, 0],
        tiles=None,
    )


    # 2. TileLayer is the correct place for no_wrap
    if _CARTO_KEY:
        _TILE_URL = (
            f"https://basemaps.cartocdn.com/rastertiles/dark_all/"
            f"{{z}}/{{x}}/{{y}}.png?key={_CARTO_KEY}"
        )
        folium.TileLayer(
            tiles=_TILE_URL,
            attr="&copy; CARTO",
            name="CartoDB Dark Matter",
            no_wrap=True,
        ).add_to(m)
        print("[map_test] CARTO_API_KEY found — using CartoDB Dark Matter tiles.")
    else:
        folium.TileLayer(
            tiles="OpenStreetMap",
            no_wrap=True,
        ).add_to(m)
        print("[map_test] CARTO_API_KEY not set — falling back to OpenStreetMap tiles.")

    # --- Animated relay-path line ---
    AntPath(
        locations=coords,
        color="#f39c12",
        weight=3,
        opacity=0.8,
        delay=800,
        dash_array=[10, 20],
        pulse_color="#ffffff",
    ).add_to(m)

    # --- Colour-coded markers ---
    for i, hop in enumerate(hops):
        role   = _hop_role(i, len(hops))
        colour = _COLOUR[role]
        popup  = folium.Popup(
            folium.IFrame(_popup_html(hop, role, i), width=220, height=130),
            max_width=240,
        )
        folium.CircleMarker(
            location=(hop["lat"], hop["lon"]),
            radius=10 if role == "origin" else 8,
            color=colour,
            fill=True,
            fill_color=colour,
            fill_opacity=0.9,
            popup=popup,
            tooltip=f"#{i+1} {hop['city']}, {hop['country']}",
        ).add_to(m)

    # --- Legend (plain HTML overlay) ---
    legend_html = """
    <div style="
        position: fixed; bottom: 30px; left: 30px; z-index: 1000;
        background: rgba(0,0,0,0.75); color: #fff;
        padding: 12px 16px; border-radius: 8px;
        font-family: sans-serif; font-size: 13px; line-height: 1.8;">
        <b>Email Relay Path</b><br>
        <span style="color:#e74c3c;">●</span> Origin MTA<br>
        <span style="color:#3498db;">●</span> Intermediate hop<br>
        <span style="color:#2ecc71;">●</span> Destination<br>
        <span style="color:#f39c12;">— —</span> Relay direction
    </div>
    """
    m.get_root().html.add_child(folium.Element(legend_html))

    # 3. Auto-zoom camera to frame exactly the relay hops
    m.fit_bounds(coords)

    return m


def main() -> None:
    out_path = pathlib.Path(__file__).parent / "relay_path_map.html"

    m = build_map(RELAY_IPS)
    m.save(str(out_path))

    print(f"\n[map_test] Map saved -> {out_path}")
    print("[map_test] Opening in default browser …")
    webbrowser.open(out_path.as_uri())


if __name__ == "__main__":
    main()
