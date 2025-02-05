import scapy.all as scapy
import ipaddress
import time
import requests
import argparse
import logging
from collections import defaultdict

def monitor_traffic(allowlist=None, interval=10, high_url=None, low_url=None, threshold=0.5, consecutive=2):
    """
    Monitor traffic on all network interfaces and apply CIDR allowlist filtering.

    :param allowlist: List of allowed CIDR ranges (e.g., ["192.168.0.0/24", "10.0.0.0/8"]).
    :param interval: Interval (in seconds) to aggregate and report statistics.
    :param high_url: URL to call when data rate exceeds the threshold.
    :param low_url: URL to call when data rate falls below the threshold.
    :param threshold: Data rate threshold in Mbit/s.
    :param consecutive: Number of consecutive measurements to confirm before firing an event.
    """
    if allowlist is None:
        allowlist = []

    logging.debug(f"Allowlist: {allowlist}")
    logging.debug(f"Monitoring interval: {interval} seconds")
    logging.debug(f"High URL: {high_url}, Low URL: {low_url}, Threshold: {threshold} Mbit/s, Consecutive: {consecutive}")

    # Convert CIDRs to ipaddress objects for faster checks
    allowed_networks = [ipaddress.ip_network(cidr) for cidr in allowlist]
    print(allowed_networks)

    def is_allowed(ip):
        """Check if an IP is within the allowlist."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            result = any(ip_obj in network for network in allowed_networks)
            logging.debug(f"IP {ip} is allowed: {result}")
            return result
        except ValueError:
            logging.error(f"Invalid IP address: {ip}")
            return False

    def packet_handler(packet):
        """Handle each packet to aggregate traffic statistics."""
        nonlocal traffic_stats
        if packet.haslayer(scapy.IP):
            ip_layer = packet[scapy.IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            # Check if source or destination IP matches the allowlist
            if is_allowed(src_ip):
                traffic_stats[src_ip]["sent"] += len(packet)
                logging.debug(f"Packet from {src_ip} added to sent stats.")
            if is_allowed(dst_ip):
                traffic_stats[dst_ip]["recv"] += len(packet)
                logging.debug(f"Packet to {dst_ip} added to recv stats.")

    def restart_monitoring(allowlist, interval, high_url, low_url, threshold, consecutive, max_retries=5):
        """Restart the monitoring process, including rescanning interfaces."""
        retries = 0
        while retries < max_retries:
            try:
                logging.warning("Restarting monitoring due to network error... (Attempt %d)", retries + 1)
                monitor_traffic(allowlist, interval, high_url, low_url, threshold, consecutive)
                break  # Exit if monitoring succeeds
            except Exception as e:
                retries += 1
                logging.error(f"Monitoring restart failed: {e}")
                time.sleep(5)  # Wait before retrying

        if retries >= max_retries:
            logging.critical("Maximum retries reached. Exiting monitoring.")
            raise SystemExit("Monitoring process terminated after repeated failures.")

    traffic_stats = defaultdict(lambda: {"sent": 0, "recv": 0})
    start_time = time.time()

    # State to track consecutive measurements and event triggers
    high_count = 0
    low_count = 0
    last_state = None  # Track the last state ("high", "low", or None)

    try:
        logging.info("Starting network traffic monitoring...")
        while True:
            scapy.sniff(prn=packet_handler, store=False, timeout=interval)

            # Aggregate and display traffic stats
            total_sent = sum(stats["sent"] for stats in traffic_stats.values())
            total_recv = sum(stats["recv"] for stats in traffic_stats.values())

            total_sent_mbps = (total_sent * 8) / (interval * 1_000_000)
            total_recv_mbps = (total_recv * 8) / (interval * 1_000_000)

            # Check data rate thresholds and call URLs accordingly
            if total_sent_mbps > threshold or total_recv_mbps > threshold:
                high_count += 1
                low_count = 0
                if high_count >= consecutive and last_state != "high":
                    if high_url:
                        requests.get(high_url)
                        logging.info(f"High data rate detected (> {threshold} Mbit/s) for {consecutive} consecutive measurements. Called high-data-rate URL.")
                    last_state = "high"
            else:
                low_count += 1
                high_count = 0
                if low_count >= consecutive and last_state != "low":
                    if low_url:
                        requests.get(low_url)
                        logging.info(f"Data rate dropped (<= {threshold} Mbit/s) for {consecutive} consecutive measurements. Called low-data-rate URL.")
                    last_state = "low"

            logging.info(f"[TOTAL] Sent: {total_sent_mbps:.2f} Mbit/s | Received: {total_recv_mbps:.2f} Mbit/s | State: {last_state} | High: {high_count} | Low: {low_count}")

            # Reset stats and timer
            traffic_stats.clear()
            start_time = time.time()

    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        restart_monitoring(allowlist, interval, high_url, low_url, threshold, consecutive)

if __name__ == "__main__":


    parser = argparse.ArgumentParser(description="Monitor network traffic with CIDR filtering and alerting.")
    parser.add_argument("--allowlist", nargs="*", default=["52.112.0.0/14", "52.122.0.0/15", "2603:1063::/38", "74.125.250.0/24", "2001:4860:4864:5::0/64", "142.250.82.0/24", "2001:4860:4864:6::/64"],
                        help="List of allowed CIDR ranges. Defaults to MS Teams & Google Meet IP ranges.")
    parser.add_argument("--interval", type=int, default=10, help="Monitoring interval in seconds.")
    parser.add_argument("--high-url", type=str, required=True, help="URL to call when data rate exceeds threshold.")
    parser.add_argument("--low-url", type=str, required=True, help="URL to call when data rate falls below threshold.")
    parser.add_argument("--threshold", type=float, default=0.5, help="Data rate threshold in Mbit/s.")
    parser.add_argument("--consecutive", type=int, default=2, help="Number of consecutive measurements to confirm before firing an event.")
    parser.add_argument("--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level.")

    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level.upper()),
                        format="%(asctime)s - %(levelname)s - %(message)s")

    monitor_traffic(allowlist=args.allowlist, interval=args.interval, high_url=args.high_url, low_url=args.low_url, threshold=args.threshold, consecutive=args.consecutive)
