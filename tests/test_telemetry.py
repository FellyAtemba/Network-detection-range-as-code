import os
import time
import pytest
from tests.conftest import run_container_cmd, check_connection

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def test_sensor_mirror_receives_traffic(octet2):
    """The gateway's tc mirror to eth9 actually delivers packets to the sensor:
    Suricata's eve.json gains a new event for the triggered flow, not just an
    existing (possibly empty) log directory."""
    sensor = "clab-netforge-a3-sensor"
    finance_ip = f"10.{octet2}.20.10"
    server_ip = f"10.{octet2}.50.10"
    eve_path = "/var/log/suricata/eve.json"

    before = run_container_cmd(sensor, f"wc -l {eve_path}")
    before_lines = int(before.stdout.split()[0]) if before.returncode == 0 and before.stdout.strip() else 0

    check_connection("finance", server_ip, 443)
    time.sleep(2)

    after = run_container_cmd(sensor, f"tail -n +{before_lines + 1} {eve_path}")
    assert after.returncode == 0, "could not read eve.json on the sensor"
    new_events = [l for l in after.stdout.strip().splitlines() if l.strip()]
    assert any(finance_ip in line and "443" in line for line in new_events), (
        f"no new eve.json event for {finance_ip} -> {server_ip}:443 after the trigger "
        f"({len(new_events)} new line(s) seen)"
    )
    
def test_sensor_cannot_initiate_traffic(octet2):
    """Passive sensor must not be able to initiate traffic into protected zones."""
    res = run_container_cmd("clab-netforge-a3-sensor", f"nc -zv -w 2 10.{octet2}.50.10 443", timeout=3)
    assert res.returncode != 0
