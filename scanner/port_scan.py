"""
port_scan.py - Stealthy TCP Port Scanner
=========================================
This module scans a target IP for open TCP ports using raw sockets.
It connects to each port using socket.connect_ex() and checks if
the port is open (returns 0) or closed (returns an error code).

STEALTH FEATURES:
- Ports are scanned in RANDOM order (not sequential 1,2,3...)
  so it looks less like a scan to intrusion detection systems
- Configurable delay + random jitter between each connection
  to blend in with normal traffic
- Short socket timeout to avoid lingering connections
- Clean socket shutdown after every probe

USAGE (standalone test):
    python scanner/port_scan.py <target_ip> <start_port> <end_port>
    python scanner/port_scan.py 192.168.100.50 1 1024
"""

import socket       # For creating TCP connections to test ports
import threading    # For scanning multiple ports at the same time
import time         # For delays and measuring response time
import random       # For randomizing port order and adding jitter
import sys          # For reading command line arguments


# ============================================================
# CONFIGURATION - tweak these to control scan behavior
# ============================================================

DEFAULT_TIMEOUT = 0.5       # Seconds to wait for a port to respond
DEFAULT_MAX_THREADS = 50    # Max number of simultaneous scans
DEFAULT_DELAY = 0.0         # Base delay (seconds) between each probe
DEFAULT_JITTER = 0.0        # Max random extra delay added to base delay
                            # Set delay=0.05 jitter=0.05 for quieter scans


# ============================================================
# SHARED DATA - these are used by all scanning threads
# ============================================================

open_ports = []             # List to store results: (port, response_time_ms)
open_ports_lock = threading.Lock()  # Lock so threads don't corrupt the list
scan_count = 0              # How many ports we've checked so far
scan_count_lock = threading.Lock()  # Lock for the counter
total_ports = 0             # Total ports to scan (for progress display)


def scan_single_port(target_ip, port, timeout):
    """
    Try to connect to ONE port on the target IP.

    How it works:
    1. Create a TCP socket
    2. Set a timeout so we don't wait forever
    3. Try to connect using connect_ex() which returns 0 if open
    4. If open, record the port and how long it took
    5. Always close the socket cleanly when done

    Args:
        target_ip (str): The IP address to scan (e.g. "192.168.100.50")
        port (int):      The port number to check (e.g. 21, 80, 443)
        timeout (float): How long to wait for a response in seconds
    """
    global scan_count

    try:
        # Create a fresh TCP socket for this one port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set timeout - if the port doesn't respond in time, move on
        sock.settimeout(timeout)

        # Record the time BEFORE we try to connect
        start_time = time.time()

        # connect_ex returns 0 if connection succeeded (port is open)
        # returns an error code number if it failed (port is closed/filtered)
        result = sock.connect_ex((target_ip, port))

        # Calculate how long the connection took in milliseconds
        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        if result == 0:
            # Port is OPEN - save it to our results list
            # We use a lock because multiple threads write to this list
            with open_ports_lock:
                open_ports.append((port, elapsed_ms))

        # Cleanly shut down and close the socket
        # This avoids leaving half-open connections (stealthier)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            # Socket might already be disconnected, that's fine
            pass
        sock.close()

    except socket.timeout:
        # Port didn't respond in time - treat as closed/filtered
        pass
    except OSError:
        # Network error (host unreachable, etc.) - skip this port
        pass

    # Update and display progress counter
    with scan_count_lock:
        scan_count += 1
        # Show progress every 50 ports so we know it's working
        if scan_count % 50 == 0 or scan_count == total_ports:
            percent = round((scan_count / total_ports) * 100, 1)
            print(f"  [{scan_count}/{total_ports}] {percent}% scanned...", flush=True)


def run_port_scan(target_ip, start_port, end_port,
                  timeout=DEFAULT_TIMEOUT,
                  max_threads=DEFAULT_MAX_THREADS,
                  delay=DEFAULT_DELAY,
                  jitter=DEFAULT_JITTER):
    """
    Scan a range of TCP ports on a target IP address.

    This is the MAIN function you call to start a scan. It:
    1. Builds a list of all ports to scan
    2. SHUFFLES them into random order (stealth!)
    3. Launches threads to scan them (up to max_threads at once)
    4. Waits for all threads to finish
    5. Returns the results sorted by port number

    Args:
        target_ip (str):    IP address to scan
        start_port (int):   First port in range (e.g. 1)
        end_port (int):     Last port in range (e.g. 1024)
        timeout (float):    Socket timeout in seconds per port
        max_threads (int):  Maximum simultaneous scanning threads
        delay (float):      Base delay between launching each probe
        jitter (float):     Random 0-to-jitter seconds added to delay

    Returns:
        list of tuples: [(port_number, response_time_ms), ...]
        sorted by port number, only includes OPEN ports
    """
    global open_ports, scan_count, total_ports

    # Reset shared data (in case this function is called multiple times)
    open_ports = []
    scan_count = 0

    # Build the list of ports and SHUFFLE for stealth
    # Sequential scanning (1, 2, 3, 4...) is a red flag for IDS systems
    # Random order (847, 23, 512, 80...) looks more like normal traffic
    port_list = list(range(start_port, end_port + 1))
    random.shuffle(port_list)
    total_ports = len(port_list)

    print(f"\n[*] Starting TCP port scan on {target_ip}")
    print(f"[*] Port range: {start_port}-{end_port} ({total_ports} ports)")
    print(f"[*] Max threads: {max_threads} | Timeout: {timeout}s")
    if delay > 0 or jitter > 0:
        print(f"[*] Delay: {delay}s base + 0-{jitter}s jitter (stealth mode)")
    print(f"[*] Port order: randomized\n")

    # We use a semaphore to limit how many threads run at once
    # Think of it like a bouncer at a club - only lets max_threads in
    thread_limiter = threading.Semaphore(max_threads)

    # List to keep track of all our thread objects
    threads = []

    # Record when the scan started
    scan_start = time.time()

    for port in port_list:
        # Wait for a thread slot to open up
        thread_limiter.acquire()

        # Add delay + random jitter between probes for stealth
        # This makes the scan timing irregular and harder to detect
        if delay > 0 or jitter > 0:
            wait_time = delay + random.uniform(0, jitter)
            time.sleep(wait_time)

        def thread_worker(p):
            """Wrapper that releases the semaphore when the scan finishes."""
            try:
                scan_single_port(target_ip, p, timeout)
            finally:
                # Always release the slot, even if something crashes
                thread_limiter.release()

        # Create and start a new thread for this port
        t = threading.Thread(target=thread_worker, args=(port,))
        t.daemon = True  # Thread will die if main program exits
        t.start()
        threads.append(t)

    # Wait for ALL threads to finish before returning results
    for t in threads:
        t.join()

    # Calculate total scan duration
    scan_duration = round(time.time() - scan_start, 2)

    # Sort results by port number (they came in random order)
    open_ports.sort(key=lambda x: x[0])

    # Print summary
    print(f"\n[+] Scan complete in {scan_duration} seconds")
    print(f"[+] Found {len(open_ports)} open port(s)\n")

    if open_ports:
        # Print a nice table of results
        print(f"  {'PORT':<10} {'STATE':<10} {'RESPONSE TIME':<15}")
        print(f"  {'-'*10} {'-'*10} {'-'*15}")
        for port, resp_time in open_ports:
            print(f"  {port:<10} {'open':<10} {resp_time} ms")
        print()

    return open_ports


# ============================================================
# STANDALONE MODE - runs when you execute this file directly
# ============================================================

if __name__ == "__main__":
    """
    When you run this file directly from the command line:
        python scanner/port_scan.py <target_ip> <start_port> <end_port>

    Example:
        python scanner/port_scan.py 192.168.100.50 1 1024
    """

    # Check that the user provided the right number of arguments
    if len(sys.argv) < 4:
        print("Usage: python scanner/port_scan.py <target_ip> <start_port> <end_port>")
        print("Example: python scanner/port_scan.py 192.168.100.50 1 1024")
        sys.exit(1)

    # Read arguments from command line
    target = sys.argv[1]           # First argument: target IP
    start = int(sys.argv[2])       # Second argument: start port
    end = int(sys.argv[3])         # Third argument: end port

    # Validate the IP address format
    try:
        socket.inet_aton(target)   # This throws an error if IP is invalid
    except socket.error:
        print(f"[!] Invalid IP address: {target}")
        sys.exit(1)

    # Validate port range
    if start < 1 or end > 65535 or start > end:
        print(f"[!] Invalid port range: {start}-{end}")
        print("    Ports must be between 1 and 65535, start must be <= end")
        sys.exit(1)

    # Run the scan and get results
    results = run_port_scan(target, start, end)

    # Exit with code 0 if we found open ports, 1 if none found
    if results:
        sys.exit(0)
    else:
        print("[*] No open ports found in the specified range.")
        sys.exit(1)
