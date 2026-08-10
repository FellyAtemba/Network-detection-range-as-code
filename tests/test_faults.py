import os
import subprocess
import pytest
from tests.conftest import run_container_cmd, check_connection

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run_fault_script(action):
    script_path = os.path.join(ROOT_DIR, "scripts", "inject_fault.py")
    res = subprocess.run(f"python3 {script_path} {action}", shell=True, capture_output=True, text=True)
    return res

def test_fault1_established_return_failure(octet2):
    """Fault 1: Established return handling removed for finance path."""
    try:
        run_fault_script("fault1")
        # Finance to Server 443 should FAIL under Fault 1 because return SYN-ACK is dropped
        assert check_connection("finance", f"10.{octet2}.50.10", 443, timeout=2) is False
    finally:
        run_fault_script("restore")
    # Verify green baseline restored
    assert check_connection("finance", f"10.{octet2}.50.10", 443, timeout=2) is True

def test_fault2_broadened_management_ingress(octet2):
    """Fault 2: Management ingress broadened to allow Users zone."""
    try:
        run_fault_script("fault2")
        # Users to Server 22 unexpectedly SUCCEEDS under Fault 2
        assert check_connection("users", f"10.{octet2}.50.10", 22, timeout=2) is True
    finally:
        run_fault_script("restore")
    # Verify green baseline restored (Users SSH should be DENIED)
    assert check_connection("users", f"10.{octet2}.50.10", 22, timeout=2) is False

def test_fault3_dmz_sensor_mirror_missing(octet2):
    """Fault 3: DMZ interface mirror rule missing on gateway."""
    try:
        run_fault_script("fault3")
        # Check tc filter on eth8 on gateway
        res = run_container_cmd("clab-netforge-a3-gateway", "tc filter show dev eth8 ingress")
        assert "mirred" not in res.stdout
    finally:
        run_fault_script("restore")
    # Verify green baseline restored
    res = run_container_cmd("clab-netforge-a3-gateway", "tc filter show dev eth8 ingress")
    assert "mirred" in res.stdout

def test_fault4_asymmetric_return_failure(octet2):
    """Fault 4 (D1): Finance return path set asymmetric through core."""
    try:
        run_fault_script("fault4")
        # Finance TCP connection to Server fails/times out under asymmetric routing
        assert check_connection("finance", f"10.{octet2}.50.10", 443, timeout=2) is False
    finally:
        run_fault_script("restore")
    # Verify green baseline restored
    assert check_connection("finance", f"10.{octet2}.50.10", 443, timeout=2) is True
