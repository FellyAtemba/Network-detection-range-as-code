import json
import os
import subprocess
import pytest

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

@pytest.fixture(scope="session")
def variant():
    var_path = os.path.join(ROOT_DIR, "configs", "variant.json")
    with open(var_path, "r") as f:
        return json.load(f)

@pytest.fixture(scope="session")
def octet2(variant):
    return variant.get("second_octet", 51)

def run_container_cmd(container, cmd, timeout=5):
    full_cmd = f"docker exec {container} {cmd}"
    res = subprocess.run(full_cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return res

def check_connection(src_zone, dst_ip, port, proto="tcp", timeout=2):
    """Test network connectivity from a zone container to a destination.
    
    Returns True if the connection succeeds, False otherwise.
    Named check_connection (not test_connection) to avoid pytest collection.
    """
    container = f"clab-netforge-a3-{src_zone}"
    if proto == "tcp":
        cmd = f"nc -zv -w {timeout} {dst_ip} {port}"
    else:
        # nc -uzv is unreliable on Alpine (UDP connect() always succeeds).
        # Use Python to send a UDP datagram and wait for a response.
        # If the firewall blocks the packet, recvfrom times out and Python exits with code 1.
        cmd = (
            f"python3 -c \""
            f"import socket;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
            f"s.settimeout({timeout});"
            f"s.sendto(b'probe',('{dst_ip}',{port}));"
            f"s.recvfrom(1024)\""
        )
    try:
        res = run_container_cmd(container, cmd, timeout=timeout+3)
        return res.returncode == 0
    except subprocess.TimeoutExpired:
        return False
