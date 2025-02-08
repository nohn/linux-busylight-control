"""
Monitor network traffic to certain IP ranges and trigger URLs if bandwidth goes above / falls below a threshold.
"""
import argparse
import ipaddress
import logging
import time
from collections import defaultdict

import psutil
import requests
import scapy.all as scapy
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6


def get_network_interfaces():
    """Retrieve the current list of network interfaces and their IP addresses."""
    interfaces = {}
    for iface, addrs in psutil.net_if_addrs().items():
        ip_list = [addr.address for addr in addrs if addr.family in {2, 10}]  # IPv4 and IPv6
        if ip_list: # Only add interface if it has assigned IP addresses
            interfaces[iface] = ip_list
    return interfaces

def monitor_traffic(allowlist=None, ignorelist=None, interval=10, high_url=None, low_url=None, threshold=0.5, consecutive=2):
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
    logging.debug(f"Ignorelist: {ignorelist}")
    logging.debug(f"Monitoring interval: {interval} seconds")
    logging.debug(f"High URL: {high_url}, Low URL: {low_url}, Threshold: {threshold} Mbit/s, Consecutive: {consecutive}")

    # Convert CIDRs to ipaddress objects for faster checks
    allowed_networks = [ipaddress.ip_network(cidr) for cidr in allowlist]
    ignored_networks = [ipaddress.ip_network(cidr) for cidr in ignorelist] if ignorelist else []

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

    def process_ip_packet(ip_layer, packet):
        """Handles common processing for both IPv4 and IPv6 packets."""
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        packet_size = len(packet)

        # Check traffic involving LOCAL interfaces (sent OR received)
        if src_ip in local_interface_ips:  # Traffic SENT by local interface
            if is_allowed(dst_ip):  # Destination is allowed
                traffic_stats[dst_ip]["recv"] += packet_size  # Count as received by destination (even if sent by us)
            else:
                non_allowlist_traffic[dst_ip] += packet_size
        elif dst_ip in local_interface_ips:  # Traffic RECEIVED by local interface
            if is_allowed(src_ip):  # Source is allowed
                traffic_stats[src_ip]["sent"] += packet_size  # Count as sent by source (even if received by us)
            else:
                non_allowlist_traffic[src_ip] += packet_size
        else:  # Traffic between non-local interfaces (not relevant for our monitoring)
            logging.debug(f"Traffic between non-local interfaces received! {src_ip} -> {dst_ip}")

    def packet_handler(packet):
        """Handle each packet to aggregate traffic statistics."""
        nonlocal traffic_stats, non_allowlist_traffic, local_interface_ips
        if IP in packet:
            ip_layer = packet[IP]
            process_ip_packet(ip_layer, packet)
        elif IPv6 in packet:
            ip_layer = packet[IPv6]
            process_ip_packet(ip_layer, packet)
        else:
            logging.debug(f"Non IP packet received: {packet}")

    def get_local_interface_ips():
        """Get the IP addresses of the local network interfaces."""
        local_ips = set()  # Use a set for efficient lookups
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family in {2, 10}:  # IPv4 and IPv6
                    local_ips.add(addr.address)
        return local_ips

    def is_in_ignored_network(ip, ignored_networks):
        """Check if an IP is within the ignored subnets."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in network for network in ignored_networks)
        except ValueError:
            logging.error(f"Invalid IP address: {ip}")
            return False

    def restart_monitoring(allowlist, ignorelist, interval, high_url, low_url, threshold, consecutive, max_retries=5):
        """Restart the monitoring process, including rescanning interfaces."""
        retries = 0
        while retries < max_retries:
            try:
                logging.warning(f"Restarting monitoring due to network error... (Attempt {retries + 1})")
                monitor_traffic(allowlist, ignorelist, interval, high_url, low_url, threshold, consecutive)
                break  # Exit if monitoring succeeds
            except Exception as e:
                retries += 1
                logging.error(f"Monitoring restart attempt {retries} failed: {e}", exc_info=True)
                time.sleep(5)  # Wait before retrying

        if retries >= max_retries:
            logging.critical("Maximum retries reached. Exiting monitoring.")
            raise SystemExit("Monitoring process terminated after repeated failures.")

    local_interface_ips = get_local_interface_ips()

    traffic_stats = defaultdict(lambda: {"sent": 0, "recv": 0})
    non_allowlist_traffic = defaultdict(int)  # Track traffic from IPs not in allowlist

    # State to track consecutive measurements and event triggers
    high_count = 0
    low_count = 0
    last_state = None  # Track the last state ("high", "low", or None)
    previous_interfaces = get_network_interfaces()
    logging.debug(f"Interfaces: {previous_interfaces}")

    try:
        logging.info("Starting network traffic monitoring...")
        while True:
            current_interfaces = get_network_interfaces()
            if current_interfaces != previous_interfaces:
                logging.warning("Network interfaces changed. Restarting monitoring...")
                return monitor_traffic(allowlist, interval, high_url, low_url, threshold, consecutive)

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
                        requests.get(high_url, timeout=10)
                        logging.info(f"High data rate detected (> {threshold} Mbit/s) for {consecutive} consecutive measurements. Called high-data-rate URL.")
                    last_state = "high"
            else:
                low_count += 1
                high_count = 0
                if low_count >= consecutive and last_state != "low":
                    if low_url:
                        requests.get(low_url, timeout=10)
                        logging.info(f"Data rate dropped (<= {threshold} Mbit/s) for {consecutive} consecutive measurements. Called low-data-rate URL.")
                    last_state = "low"

            # Identify the highest traffic IP not in allowlist, EXCLUDING local interface IPs
            non_allowlist_traffic_filtered = {
                ip: traffic
                for ip, traffic in non_allowlist_traffic.items()
                if ip not in local_interface_ips and not is_in_ignored_network(ip, ignored_networks)
            }
            highest_ip = None
            highest_traffic = 0.0
            if non_allowlist_traffic_filtered:  # Ensure the dictionary is not empty
                highest_ip = max(non_allowlist_traffic_filtered, key=non_allowlist_traffic_filtered.get)
                highest_traffic = non_allowlist_traffic_filtered[highest_ip] * 8 / (interval * 1_000_000)

            logging.info(f"[AllowList]: {last_state} | H: {high_count} | L: {low_count} | S: {total_sent_mbps:.2f} Mbit/s | R: {total_recv_mbps:.2f} Mbit/s | [!AllowList]: {highest_ip} @ {highest_traffic:.2f} Mbit/s")

            # Reset stats and timer
            traffic_stats.clear()
            non_allowlist_traffic.clear()

    except KeyboardInterrupt:
        logging.info("Monitoring stopped by user.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}", exc_info=True)
        restart_monitoring(allowlist, ignorelist, interval, high_url, low_url, threshold, consecutive)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor network traffic with CIDR filtering and alerting.")
    parser.add_argument("--allowlist", nargs="*", default=[
        "52.112.0.0/14",          # MS Teams
        "52.122.0.0/15",          # MS Teams
        "2603:1063::/38",         # MS Teams
        "13.107.253.0/24",        # MS Convene
        "74.125.250.0/24",        # Google Meet (Workspace)
        "2001:4860:4864:5::0/64", # Google Meet (Workspace)
        "142.250.82.0/24",        # Google Meet (Consumer)
        "2001:4860:4864:6::/64"   # Google Meet (Consumer)
    ],
                        help="List of allowed CIDR ranges. Defaults to MS Teams & Google Meet IP ranges.")
    parser.add_argument("--ignorelist", nargs="*", default=[], help="List of CIDR ranges to ignore when reporting highest non-allowlist IP.")
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

    monitor_traffic(allowlist=args.allowlist, ignorelist=args.ignorelist, interval=args.interval, high_url=args.high_url, low_url=args.low_url, threshold=args.threshold, consecutive=args.consecutive)
