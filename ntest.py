import socket
import time
import argparse
import csv
import os
from datetime import datetime


def probe(host, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        sock.connect((host, port))
        latency = (time.perf_counter() - start) * 1000
        sock.close()
        return True, round(latency, 2)
    except (socket.timeout, OSError):
        latency = (time.perf_counter() - start) * 1000
        return False, round(latency, 2)
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(description="TCP SYN/ACK probe monitor")
    parser.add_argument("--target", default="103.146.242.138", help="Target IP (default: Google)")
    parser.add_argument("--port", type=int, default=5060, help="Target port (default: 5060)")
    parser.add_argument("--lan-target", default=None, help="Optional LAN IP to probe alongside")
    parser.add_argument("--lan-port", type=int, default=7680, help="LAN target port")
    parser.add_argument("--interval", type=float, default=5, help="Seconds between probes")
    parser.add_argument("--timeout", type=float, default=2, help="Connect timeout in seconds")
    parser.add_argument("--logfile", default="probe_log.csv", help="Output CSV file")
    args = parser.parse_args()

    log_exists = os.path.exists(args.logfile)
    logfile = open(args.logfile, "a", newline="")
    writer = csv.writer(logfile)

    if not log_exists:
        writer.writerow(["timestamp", "target", "port", "success", "latency_ms"])
        logfile.flush()

    total = 0
    failures = 0

    print(f"Probing {args.target}:{args.port} every {args.interval}s (timeout={args.timeout}s)")
    if args.lan_target:
        print(f"Also probing LAN: {args.lan_target}:{args.lan_port}")
    print(f"Logging to: {args.logfile}")
    print(f"{'Timestamp':<26} {'Target':<22} {'Result':<8} {'Latency':<10}")
    print("-" * 70)

    try:
        while True:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            success, latency = probe(args.target, args.port, args.timeout)
            total += 1
            if not success:
                failures += 1

            status = "OK" if success else "FAIL"
            writer.writerow([ts, args.target, args.port, status, latency])
            marker = "" if success else " <<<< PACKET LOSS"
            print(f"{ts}  {args.target}:{args.port:<6} {status:<8} {latency:>7.2f}ms{marker}")

            if args.lan_target:
                lan_success, lan_latency = probe(args.lan_target, args.lan_port, args.timeout)
                total += 1
                if not lan_success:
                    failures += 1
                lan_status = "OK" if lan_success else "FAIL"
                writer.writerow([ts, args.lan_target, args.lan_port, lan_status, lan_latency])
                lan_marker = "" if lan_success else " <<<< LAN LOSS"
                print(f"{ts}  {args.lan_target}:{args.lan_port:<6} {lan_status:<8} {lan_latency:>7.2f}ms{lan_marker}")

            logfile.flush()
            time.sleep(args.interval)

    except KeyboardInterrupt:
        loss_pct = (failures / total * 100) if total > 0 else 0
        print(f"\n\nStopped. Total probes: {total}, Failures: {failures}, Loss: {loss_pct:.1f}%")
        logfile.close()


if __name__ == "__main__":
    main()