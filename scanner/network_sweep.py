"""
network_sweep.py - Stealthy Network Host Discovery
====================================================
This module finds live hosts on a network WITHOUT using ICMP ping.

WHY NOT PING?
- ICMP ping sweeps are the #1 thing Intrusion Detection Systems flag
- Many firewalls block ICMP entirely
- A ping sweep screams "someone is scanning your network!"

STEALTH APPROACH (TCP Connect Discovery):
- Instead of pinging, we try a quick TCP connect to common ports
- A single TCP connect to port 80 looks like normal web browsing
- We only need ONE port to respond to know the host is alive
- Randomized host order so we don't sweep sequentially
- Configurable delay + jitter between probes

USAGE (standalone):
    python scanner/network_sweep.py <subnet_cidr>
    python scanner/network_sweep.py 192.168.100.0/24
"""

import socket       # For TCP connections to detect live hosts
import threading    # For checking multiple hosts at the same time
import time         # For delays and timing
import random       # For randomizing order and jitter
import sys          # For command line arguments
import ipaddress    # For parsing CIDR notation like "192.168.100.0/24"


# ============================================================
# CONFIGURATION
# ============================================================

# Ports to probe for host discovery
# If ANY of these respond, the host is alive
# These are common ports that most servers have at least one of open
DISCOVERY_PORTS = [80, 443, 22, 21, 445, 139, 23, 25, 8080, 3389, 53, 3306]

DEFAULT_TIMEOUT = 0.5       # Seconds to wait per port probe
DEFAULT_MAX_THREADS = 30    # Max simultaneous host checks
DEFAULT_DELAY = 0.0         # Base delay between probing each host
DEFAULT_JITTER = 0.0        # Random extra delay (set 0.05-0.1 for stealth)

# How many discovery ports to try per host before giving up
# Lower = faster + stealthier, higher = more accurate
MAX_PORTS_PER_HOST = 4


# ============================================================
# SHARED DATA
# ============================================================

live_hosts = []                         # List of IPs that responded
live_hosts_lock = threading.Lock()      # Thread safety lock
sweep_count = 0                         # Progress counter
sweep_count_lock = threading.Lock()     # Lock for counter
total_hosts = 0                         # Total hosts to check


def check_host_alive(ip_str, timeout, ports_to_try):
    """
    Check if a single host is alive by attempting TCP connections.

    Instead of ping, we try connecting to a few common ports.
    If ANY port responds (open OR refused), the host is alive.
    connect_ex() returning 0 means port is open (host alive).
    connect_ex() returning 111 (connection refused) also means host alive
    (the host actively rejected us, so it exists).

    Only timeout/unreachable means the host is probably not there.

    Args:
        ip_str (str):        IP address to check (e.g. "192.168.100.50")
        timeout (float):     Seconds to wait per connection attempt
        ports_to_try (list): Which ports to probe on this host
    """
    global sweep_count

    host_is_alive = False

    # Shuffle the discovery ports for this host too
    # So not every host gets probed on port 80 first
    shuffled_ports = list(ports_to_try)
    random.shuffle(shuffled_ports)

    # Only try a limited number of ports (stealthier)
    ports_subset = shuffled_ports[:MAX_PORTS_PER_HOST]

    for port in ports_subset:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            result = sock.connect_ex((ip_str, port))

            # result == 0 means port is open → host is definitely alive
            # result == 10061 (Windows) or 111 (Linux) means "connection refused"
            #   → host IS alive, it just doesn't have that port open
            # Only timeouts and "host unreachable" mean the host is down
            if result == 0 or result == 10061 or result == 111:
                host_is_alive = True

            # Clean shutdown
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

            # Found a live host, no need to try more ports
            if host_is_alive:
                break

        except socket.timeout:
            # No response on this port, try next one
            continue
        except OSError:
            # Network error, try next port
            continue

    if host_is_alive:
        with live_hosts_lock:
            live_hosts.append(ip_str)

    # Update progress
    with sweep_count_lock:
        sweep_count += 1
        if sweep_count % 10 == 0 or sweep_count == total_hosts:
            percent = round((sweep_count / total_hosts) * 100, 1)
            print(f"  [{sweep_count}/{total_hosts}] {percent}% checked...",
                  flush=True)


def run_network_sweep(subnet_cidr, timeout=DEFAULT_TIMEOUT,
                      max_threads=DEFAULT_MAX_THREADS,
                      delay=DEFAULT_DELAY, jitter=DEFAULT_JITTER):
    """
    Discover all live hosts on a subnet using stealthy TCP probes.

    How it works:
    1. Parse the CIDR notation to get all possible host IPs
    2. Shuffle them into random order (stealth - avoids sequential sweep)
    3. For each IP, try TCP connecting to a few common ports
    4. If any port responds, mark the host as alive
    5. Return sorted list of live host IPs

    Args:
        subnet_cidr (str):  Subnet in CIDR notation (e.g. "192.168.100.0/24")
        timeout (float):    Seconds to wait per probe
        max_threads (int):  Max simultaneous host checks
        delay (float):      Base delay between probing each host
        jitter (float):     Random extra delay added to base

    Returns:
        list of str: Sorted list of live IP addresses
    """
    global live_hosts, sweep_count, total_hosts

    # Reset shared data
    live_hosts = []
    sweep_count = 0

    # Parse the CIDR notation into a network object
    # This gives us all the IPs in that subnet
    try:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
    except ValueError as e:
        print(f"[!] Invalid subnet: {subnet_cidr} - {e}")
        return []

    # Get all host addresses (excludes network and broadcast addresses)
    all_hosts = [str(ip) for ip in network.hosts()]
    total_hosts = len(all_hosts)

    if total_hosts == 0:
        print("[!] No hosts in the specified subnet")
        return []

    # Randomize the order we check hosts
    # Sequential sweep (*.1, *.2, *.3...) is obvious to IDS
    random.shuffle(all_hosts)

    print(f"\n[*] Network sweep on {subnet_cidr}")
    print(f"[*] Checking {total_hosts} possible hosts")
    print(f"[*] Method: TCP connect (stealthy, no ICMP)")
    print(f"[*] Discovery ports: {MAX_PORTS_PER_HOST} random from "
          f"{len(DISCOVERY_PORTS)} common ports")
    print(f"[*] Max threads: {max_threads} | Timeout: {timeout}s")
    if delay > 0 or jitter > 0:
        print(f"[*] Delay: {delay}s + 0-{jitter}s jitter")
    print(f"[*] Host order: randomized\n")

    # Semaphore to limit concurrent threads
    thread_limiter = threading.Semaphore(max_threads)
    threads = []
    scan_start = time.time()

    for ip_str in all_hosts:
        thread_limiter.acquire()

        # Stealth delay between probing each host
        if delay > 0 or jitter > 0:
            wait_time = delay + random.uniform(0, jitter)
            time.sleep(wait_time)

        def thread_worker(ip):
            """Wrapper that releases semaphore slot when done."""
            try:
                check_host_alive(ip, timeout, DISCOVERY_PORTS)
            finally:
                thread_limiter.release()

        t = threading.Thread(target=thread_worker, args=(ip_str,))
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for all threads to complete
    for t in threads:
        t.join()

    # Sort results by IP address (numerically, not alphabetically)
    # ipaddress module handles proper IP sorting
    live_hosts.sort(key=lambda ip: ipaddress.ip_address(ip))

    scan_duration = round(time.time() - scan_start, 2)

    # Print results
    print(f"\n[+] Sweep complete in {scan_duration} seconds")
    print(f"[+] Found {len(live_hosts)} live host(s) "
          f"out of {total_hosts} checked\n")

    if live_hosts:
        print(f"  {'#':<5} {'IP ADDRESS':<20} {'STATUS':<10}")
        print(f"  {'-'*5} {'-'*20} {'-'*10}")
        for i, ip in enumerate(live_hosts, 1):
            print(f"  {i:<5} {ip:<20} {'alive':<10}")
        print()

    return live_hosts


# ============================================================
# STANDALONE MODE
# ============================================================

if __name__ == "__main__":
    """
    Run from command line:
        python scanner/network_sweep.py 192.168.100.0/24
    """

    if len(sys.argv) < 2:
        print("Usage: python scanner/network_sweep.py <subnet_cidr>")
        print("Example: python scanner/network_sweep.py 192.168.100.0/24")
        sys.exit(1)

    subnet = sys.argv[1]

    # Validate it looks like a CIDR subnet
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        print(f"[!] Invalid CIDR notation: {subnet}")
        print("    Use format like: 192.168.100.0/24")
        sys.exit(1)

    results = run_network_sweep(subnet)

    if results:
        sys.exit(0)
    else:
        print("[*] No live hosts found on this subnet.")
        sys.exit(1)
