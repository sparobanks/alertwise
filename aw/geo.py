"""A small stand-in for a GeoIP lookup.

Real deployments look up the country of an IP address in a GeoIP database.
The simulated network uses fixed address blocks, so this table plays that
role. Private addresses (10.x, 192.168.x) are treated as the internal
company network.
"""
from __future__ import annotations

import ipaddress

BLOCKS = {
    "81.2.": "GB", "86.140.": "GB", "92.40.": "GB",      # staff on VPN / home broadband
    "45.155.": "RU", "185.220.": "DE", "103.75.": "VN", "41.203.": "NG",
    "177.54.": "BR", "61.177.": "CN", "194.26.": "NL", "5.188.": "RU",
    "193.32.": "US", "212.70.": "BG",
}
EXPECTED = {"GB"}  # countries staff normally sign in from


def country(ip: str) -> str:
    try:
        if ipaddress.ip_address(ip).is_private:
            return "INTERNAL"
    except ValueError:
        return "UNKNOWN"
    for prefix, cc in BLOCKS.items():
        if ip.startswith(prefix):
            return cc
    return "UNKNOWN"


def is_internal(ip: str) -> bool:
    return country(ip) == "INTERNAL"


def is_expected(ip: str) -> bool:
    return country(ip) in EXPECTED or is_internal(ip)
