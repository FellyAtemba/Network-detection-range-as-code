#!/usr/bin/env python3
import json
import os
import subprocess
import time

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCAPS_DIR = os.path.join(ROOT_DIR, "pcaps")

def load_octet():
    var_path = os.path.join(ROOT_DIR, "configs", "variant.json")
    with open(var_path, "r") as f:
        return json.load(f).get("second_octet", 51)

def run_cmd(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def capture_traffic(pcap_filename, trigger_fn, duration=5):
    pcap_path = os.path.join(PCAPS_DIR, pcap_filename)
    # Start tcpdump on gateway interface eth9 or eth1
    tcpdump_proc = subprocess.Popen(
        f"docker exec clab-netforge-a3-gateway tcpdump -i any -w /tmp/temp.pcap -c 100",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(1)
    trigger_fn()
    time.sleep(duration)
    tcpdump_proc.terminate()
    try:
        tcpdump_proc.wait(timeout=2)
    except Exception:
        tcpdump_proc.kill()
    run_cmd(f"docker cp clab-netforge-a3-gateway:/tmp/temp.pcap {pcap_path}")
    print(f"Captured PCAP saved to {pcap_path}")

def main():
    os.makedirs(PCAPS_DIR, exist_ok=True)
    o = load_octet()
    srv = f"10.{o}.50.10"
    
    # 1. Allowed paths PCAP: Finance -> Servers TCP/443
    capture_traffic("allowed_paths.pcap", lambda: run_cmd(f"docker exec clab-netforge-a3-finance nc -zv -w 2 {srv} 443"))
    
    # 2. Denied paths PCAP: Users -> Servers TCP/5432 (no direct DB access for users)
    capture_traffic("denied_paths.pcap", lambda: run_cmd(f"docker exec clab-netforge-a3-users nc -zv -w 2 {srv} 5432"))
    
    # 3. Fault 1 PCAP: Established return handling removed for finance path
    run_cmd(f"python3 {os.path.join(ROOT_DIR, 'scripts', 'inject_fault.py')} fault1")
    capture_traffic("fault1_established_failure.pcap", lambda: run_cmd(f"docker exec clab-netforge-a3-finance nc -zv -w 2 {srv} 443"))
    run_cmd(f"python3 {os.path.join(ROOT_DIR, 'scripts', 'inject_fault.py')} restore")
    
    # 4. Fault 2 PCAP: Management ingress broadened to Users zone
    run_cmd(f"python3 {os.path.join(ROOT_DIR, 'scripts', 'inject_fault.py')} fault2")
    capture_traffic("fault2_broadened_ingress.pcap", lambda: run_cmd(f"docker exec clab-netforge-a3-users nc -zv -w 2 {srv} 22"))
    run_cmd(f"python3 {os.path.join(ROOT_DIR, 'scripts', 'inject_fault.py')} restore")
    
    # 5. Fault 3 PCAP: DMZ interface mirror rule removed from sensor
    run_cmd(f"python3 {os.path.join(ROOT_DIR, 'scripts', 'inject_fault.py')} fault3")
    capture_traffic("fault3_sensor_mirror_missing.pcap", lambda: run_cmd(f"docker exec clab-netforge-a3-dmz nc -zv -w 2 {srv} 443"))
    run_cmd(f"python3 {os.path.join(ROOT_DIR, 'scripts', 'inject_fault.py')} restore")
    
    # 6. Fault 4 (D1) PCAP: Finance return path set asymmetric through core
    run_cmd(f"python3 {os.path.join(ROOT_DIR, 'scripts', 'inject_fault.py')} fault4")
    capture_traffic("fault4_asymmetric_return.pcap", lambda: run_cmd(f"docker exec clab-netforge-a3-finance nc -zv -w 2 {srv} 443"))
    
    # Restore clean baseline after all captures
    run_cmd(f"python3 {os.path.join(ROOT_DIR, 'scripts', 'inject_fault.py')} restore")

if __name__ == "__main__":
    main()
