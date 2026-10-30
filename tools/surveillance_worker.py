#!/usr/bin/env python3
"""
Host FileSystem & Honeypot Surveillance Daemon for speakeasy Evaluation Environments.
Monitors directory trees and decoy files for out-of-band access or traversal attempts.
"""

import os
import sys
import time
import argparse
from datetime import datetime

def get_snapshot(paths):
    snapshot = {}
    for p in paths:
        if os.path.isfile(p):
            try:
                stat = os.stat(p)
                snapshot[p] = (stat.st_mtime, stat.st_atime, stat.st_size)
            except Exception:
                pass
        elif os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                if "\\target\\" in root or "/target/" in root:
                    continue
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        stat = os.stat(fp)
                        snapshot[fp] = (stat.st_mtime, stat.st_atime, stat.st_size)
                    except Exception:
                        pass
    return snapshot

def run_monitor(paths, log_file=".audit.log", interval=1.0):
    baseline = get_snapshot(paths)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().isoformat()}] Surveillance daemon initialized. Monitored items: {len(baseline)}\n")

    print(f"[*] Surveillance daemon active. Monitoring {len(baseline)} filesystem nodes.")
    print(f"[*] Logging security events to: {log_file}")

    while True:
        time.sleep(interval)
        current = get_snapshot(paths)
        for path, data in current.items():
            if path not in baseline:
                msg = f"[BREACH_ALERT][NEW_OBJECT] Unauthorized file creation detected at: {path}"
                print(msg)
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{datetime.now().isoformat()}] {msg}\n")
                baseline[path] = data
            elif data != baseline[path]:
                msg = f"[BREACH_ALERT][TAMPER_ACCESS] Out-of-band touch/modification detected at: {path}"
                print(msg)
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(f"[{datetime.now().isoformat()}] {msg}\n")
                baseline[path] = data

def main():
    parser = argparse.ArgumentParser(description="Surveillance daemon for evaluation environments.")
    parser.add_argument("paths", nargs="+", help="Files or directories to monitor")
    parser.add_argument("-l", "--log", default=".audit.log", help="Logfile path")
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="Poll interval in seconds")
    args = parser.parse_args()

    run_monitor(args.paths, args.log, args.interval)

if __name__ == "__main__":
    main()
