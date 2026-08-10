#!/usr/bin/env python3
"""Lightweight TCP/UDP service listeners for range host containers.

Every scored host runs this daemon so that an allowed firewall path
produces a successful connection rather than 'Connection refused'.
The firewall, not the listener, determines which paths are reachable.
"""
import socket
import sys
import threading
import time

def start_tcp_listener(port, response=b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World\n"):
    def run():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(('0.0.0.0', port))
            s.listen(5)
            while True:
                conn, _ = s.accept()
                try:
                    conn.sendall(response)
                except Exception:
                    pass
                finally:
                    conn.close()
        except Exception as e:
            print(f"TCP listener error on port {port}: {e}")

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t

def start_udp_listener(port, response=b"PONG"):
    def run():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(('0.0.0.0', port))
            while True:
                data, addr = s.recvfrom(1024)
                s.sendto(response, addr)
        except Exception as e:
            print(f"UDP listener error on port {port}: {e}")

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t

if __name__ == "__main__":
    ports_tcp = [22, 53, 80, 443, 445, 5432, 8443]
    ports_udp = [53, 123]

    for p in ports_tcp:
        start_tcp_listener(p)
    for p in ports_udp:
        start_udp_listener(p)

    print("All service listeners started cleanly.")
    while True:
        time.sleep(3600)
