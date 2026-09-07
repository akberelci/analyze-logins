"""

Simple Login Log Analyzer
--------------------------
Reads a login log file, counts failed login attempts per user/IP,
and flags anyone who exceeds a suspicious threshold (default: 3 failed attempts).

Usage:
    python analyze_logins.py sample_login.log
"""

import sys
from collections import defaultdict

FAILED_THRESHOLD = 3  # more than this many failed attempts = suspicious


def parse_log_line(line):
    """
    Extracts the status (SUCCESS/FAILED), username, and ip from one log line.
    Example line:
    2026-09-06 08:15:22 LOGIN_FAILED user=bob ip=192.168.1.15
    """
    parts = line.strip().split()
    if len(parts) < 5:
        return None  # skip malformed lines

    status = parts[2]  # LOGIN_SUCCESS or LOGIN_FAILED
    user = parts[3].replace("user=", "")
    ip = parts[4].replace("ip=", "")
    return status, user, ip


def analyze_log(filepath):
    failed_counts = defaultdict(int)  # key: (user, ip) -> count of failed attempts

    with open(filepath, "r") as f:
        for line in f:
            parsed = parse_log_line(line)
            if not parsed:
                continue
            status, user, ip = parsed

            if status == "LOGIN_FAILED":
                failed_counts[(user, ip)] += 1

    return failed_counts


def report_suspicious(failed_counts):
    print("=== Login Analysis Report ===\n")

    suspicious_found = False
    for (user, ip), count in failed_counts.items():
        if count > FAILED_THRESHOLD:
            suspicious_found = True
            print(f"⚠️  SUSPICIOUS: user={user} ip={ip} -> {count} failed attempts")
        else:
            print(f"    OK: user={user} ip={ip} -> {count} failed attempts")

    if not suspicious_found:
        print("\nNo suspicious activity detected.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python analyze_logins.py <logfile>")
        sys.exit(1)

    log_file = sys.argv[1]
    counts = analyze_log(log_file)
    report_suspicious(counts)
