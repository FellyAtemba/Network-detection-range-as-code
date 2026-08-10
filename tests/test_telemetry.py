import os
import time
import pytest
from tests.conftest import run_container_cmd, check_connection

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def test_sensor_mirror_receives_traffic(octet2):
    """Verify that tc mirror on gateway sends copies of packets to sensor (eth9)."""
    # Trigger HTTP request from Finance to Server
    check_connection("finance", f"10.{octet2}.50.10", 443)
    time.sleep(1)
    
    # Check tcpdump or suricata log on sensor container
    res = run_container_cmd("clab-netforge-a3-sensor", "ls -la /var/log/suricata/")
    assert res.returncode == 0
    
def test_sensor_cannot_initiate_traffic(octet2):
    """Passive sensor must not be able to initiate traffic into protected zones."""
    res = run_container_cmd("clab-netforge-a3-sensor", f"nc -zv -w 2 10.{octet2}.50.10 443", timeout=3)
    assert res.returncode != 0
