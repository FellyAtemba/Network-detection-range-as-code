import csv
import json
import os
import pytest
from tests.conftest import run_container_cmd, check_connection

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_public_fixtures():
    fixtures_file = os.path.join(ROOT_DIR, "evidence", "brief", "public-fixtures.json")
    if not os.path.exists(fixtures_file):
        fixtures_file = os.path.join(ROOT_DIR, "public-fixtures.json")
    if os.path.exists(fixtures_file):
        with open(fixtures_file, "r") as f:
            data = json.load(f)
            return data.get("fixtures", [])
    return []

def get_zone_ip(zone, octet2):
    ip_map = {
        "management": f"10.{octet2}.10.10",
        "finance": f"10.{octet2}.20.10",
        "engineering": f"10.{octet2}.30.10",
        "users": f"10.{octet2}.40.10",
        "servers": f"10.{octet2}.50.10",
        "dmz": f"10.{octet2}.60.10",
        "guest": f"10.{octet2}.70.10",
        "core": f"10.{octet2}.254.1",
        "internet": f"10.{octet2}.254.1",
        "sensor": f"10.{octet2}.50.10", # Passive sensor target test
    }
    return ip_map.get(zone, f"10.{octet2}.50.10")

PUBLIC_FIXTURES = load_public_fixtures()

@pytest.mark.parametrize("fixture", PUBLIC_FIXTURES, ids=[f["case_id"] for f in PUBLIC_FIXTURES])
def test_public_fixture_path(fixture, octet2):
    src_zone = fixture["source"]
    dst_zone = fixture["destination"]
    service = fixture["service"]
    expected_verdict = fixture["expected_network"]

    proto, port_str = service.split("/")
    port = int(port_str)

    dst_ip = get_zone_ip(dst_zone, octet2)

    # Passive sensor cannot originate traffic
    if src_zone == "sensor":
        assert expected_verdict == "deny"
        return

    result = check_connection(src_zone, dst_ip, port, proto=proto, timeout=2)
    if expected_verdict == "allow":
        assert result is True, f"Expected {src_zone} -> {dst_zone} ({service}) to be ALLOWED, but it was DENIED"
    else:
        assert result is False, f"Expected {src_zone} -> {dst_zone} ({service}) to be DENIED, but it was ALLOWED"
