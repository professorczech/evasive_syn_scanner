#!/usr/bin/env python3
"""
Advanced Evasive SYN Scanner (v3 - Timing, Jitter, Decoys)

Applies more advanced evasion techniques focusing on timing ("Low and Slow"),
subtle packet variations (TTL/Window Size Jitter), and optional decoys,
while aiming to maintain scan accuracy (unlike fragmentation).

Techniques Implemented:
  - Random Source Ports
  - "Low and Slow" Variable Timing Delays (Configurable)
  - IP TTL Jitter (Configurable Range)
  - TCP Window Size Jitter (Configurable Range)
  - Decoy SYN Packets (Optional, Configurable) - Use with Caution!
  - Basic TCP Options (MSS)
  - Target Port Randomization

WARNING: Educational purposes ONLY. Unauthorized scanning is illegal.
         Requires root/administrator privileges. Network traffic IS generated.
"""
import sys
import random
import time
import os
import ipaddress # For generating decoy IPs safely

# Attempt to import Scapy components
try:
    from scapy.all import IP, TCP, ICMP, sr1, send, conf
    conf.verb = 0 # Suppress Scapy's default verbosity
except ImportError:
    print("[!] Error: Scapy library not found or import failed.")
    print("Please install Scapy: pip install scapy")
    sys.exit(1)
except Exception as e:
    print(f"[!] Error importing Scapy or setting conf: {e}")
    sys.exit(1)


# --- Configuration ---
DEFAULT_TARGET_IP = "192.168.100.101" # Default Victim IP
DEFAULT_TARGET_PORTS = [
    80, 22, 443, 21, 23, 25, 110, 139, 445, 3389, 1443, # Common
    2222, 2323, 2121, 1389, 1445, 1137 # Specified Lab Ports
]
DEFAULT_TARGET_PORTS = sorted(list(set(DEFAULT_TARGET_PORTS)))

DEFAULT_SOURCE_IP = None # Let Scapy/OS choose source IP by default

# --- Timing & Rate Configuration ---
# Make scan significantly slower by default for "Low and Slow"
MIN_DELAY = 5.0         # Minimum seconds between probes
MAX_DELAY = 15.0        # Maximum seconds between probes
DEFAULT_TIMEOUT = 4.0   # Response timeout (needs to be reasonable)

# --- Packet Jitter Configuration ---
MIN_TTL = 55            # Minimum TTL for outgoing packets
MAX_TTL = 70            # Maximum TTL (don't exceed common OS defaults by much)
MIN_WINDOW_SIZE = 1024  # Minimum TCP Window Size
MAX_WINDOW_SIZE = 65535 # Maximum TCP Window Size (standard max)

# --- Decoy Configuration ---
USE_DECOYS = False       # Enable sending decoy packets
NUM_DECOYS = 3          # Number of decoy packets per real probe
# Use private IP ranges for decoys to avoid hitting real external hosts
DECOY_IP_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# --- Other Settings ---
RANDOMIZE_PORTS = True  # Scan ports in random order
SEND_RST_ON_OPEN = True # Send RST packet if SYN/ACK is received
VERBOSE_SCAPY_SEND_RECV = False # Set True for detailed Scapy send/recv logs

# --- Evasion Helper Functions ---

def get_random_source_port():
    """Returns a random ephemeral port number."""
    return random.randint(1025, 65535)

def get_random_private_ip():
    """Generates a random IP from defined private ranges."""
    try:
        selected_range = ipaddress.ip_network(random.choice(DECOY_IP_RANGES))
        # Generate a random IP within the selected range
        # Ensure it's not the network or broadcast address if possible
        max_attempts = 10
        for _ in range(max_attempts):
             ip_int = random.randint(int(selected_range.network_address) + 1,
                                    int(selected_range.broadcast_address) - 1)
             ip = ipaddress.ip_address(ip_int)
             # Simple check: avoid using common gateway/host IPs like x.x.x.1 or x.x.x.254? Optional.
             # if str(ip).endswith('.1') or str(ip).endswith('.254'): continue
             return str(ip)
        # Fallback if couldn't find a "good" random one quickly
        return str(ipaddress.ip_address(random.randint(int(selected_range.network_address) + 1, int(selected_range.broadcast_address) - 1)))
    except Exception as e:
        print(f"[WARN] Error generating decoy IP: {e}. Using fallback.")
        return "192.168.1.100" # Generic fallback

def add_tcp_options_jitter(tcp_layer):
    """Adds MSS option and randomized Window Size."""
    tcp_options = [('MSS', 1460)] # Standard MSS
    tcp_layer.options = tcp_options
    # Add Window Size Jitter
    tcp_layer.window = random.randint(MIN_WINDOW_SIZE, MAX_WINDOW_SIZE)
    return tcp_layer

# --- Core Scan Function ---

def advanced_syn_scan(target_ip, target_ports, source_ip=None, timeout=DEFAULT_TIMEOUT,
                     min_delay=MIN_DELAY, max_delay=MAX_DELAY,
                     use_decoys=USE_DECOYS, num_decoys=NUM_DECOYS):
    """
    Performs an evasive SYN scan using advanced timing, jitter, and optional decoys.

    Args:
        target_ip (str): Target IP.
        target_ports (list): List of target ports.
        source_ip (str, optional): Source IP to use. Defaults to None.
        timeout (float): Timeout for receiving replies.
        min_delay (float): Minimum delay between probes.
        max_delay (float): Maximum delay between probes.
        use_decoys (bool): Whether to send decoy packets.
        num_decoys (int): Number of decoys per real probe if use_decoys is True.
    """
    open_ports = []
    closed_ports = []
    filtered_ports = []

    scan_ports = list(target_ports)
    if RANDOMIZE_PORTS:
        print("[*] Randomizing target port order.")
        random.shuffle(scan_ports)

    print(f"[*] Starting Advanced SYN scan against {target_ip}...")
    print(f"[*] Ports to scan ({len(scan_ports)}): {scan_ports}")
    print(f"[*] Options: Timeout={timeout}s, Delay={min_delay:.1f}-{max_delay:.1f}s")
    print(f"[*] Jitter: TTL={MIN_TTL}-{MAX_TTL}, Window={MIN_WINDOW_SIZE}-{MAX_WINDOW_SIZE}")
    print(f"[*] Decoys Enabled: {use_decoys}, Number per probe: {num_decoys if use_decoys else 'N/A'}")

    for target_port in scan_ports:
        response = None
        # Apply "Low and Slow" delay
        delay = random.uniform(min_delay, max_delay)
        print(f"[*] Port {target_port}: Waiting {delay:.2f} seconds...")
        time.sleep(delay)

        # --- Craft Real Packet ---
        real_source_port = get_random_source_port()
        real_ip_layer = IP(
            dst=target_ip,
            src=source_ip, # If None, Scapy fills it in
            ttl=random.randint(MIN_TTL, MAX_TTL) # TTL Jitter
        )
        # If source_ip was None, get the actual source IP Scapy chose
        actual_source_ip = real_ip_layer.src

        real_tcp_layer = TCP(
            sport=real_source_port,
            dport=target_port,
            flags="S"
        )
        real_tcp_layer = add_tcp_options_jitter(real_tcp_layer) # Add MSS and Window Jitter
        real_packet = real_ip_layer / real_tcp_layer

        print(f"[*] Port {target_port}: Sending REAL SYN from {actual_source_ip}:{real_source_port}")

        # --- Send Decoy Packets (Optional) ---
        if use_decoys and num_decoys > 0:
            print(f"[*]   Sending {num_decoys} decoy SYN packets...")
            for i in range(num_decoys):
                decoy_ip = get_random_private_ip()
                # Ensure decoy isn't our real IP
                if decoy_ip == actual_source_ip:
                     decoy_ip = get_random_private_ip() # Try again

                decoy_sport = get_random_source_port()
                decoy_pkt = IP(src=decoy_ip, dst=target_ip, ttl=random.randint(MIN_TTL, MAX_TTL)) / \
                            TCP(sport=decoy_sport, dport=target_port, flags="S", window=random.randint(MIN_WINDOW_SIZE, MAX_WINDOW_SIZE))
                # Send decoy without waiting for reply
                send(decoy_pkt, verbose=VERBOSE_SCAPY_SEND_RECV, iface=conf.iface)
                # Optional small delay between decoys?
                # time.sleep(random.uniform(0.01, 0.05))
            print(f"[*]   Decoys sent.")

        # --- Send Real Packet & Receive ---
        try:
            response = sr1(real_packet, timeout=timeout, verbose=VERBOSE_SCAPY_SEND_RECV, iface=conf.iface)

            # --- Analyze Response ---
            # (Analysis logic remains largely the same as v2)
            if response is None:
                print(f"[!] Port {target_port}: FILTERED (No response received).")
                print("    (Check network path, firewalls, timeout value. Consider disabling decoys if enabled.)")
                filtered_ports.append(target_port)
            elif response.haslayer(TCP):
                received_tcp = response.getlayer(TCP)
                if received_tcp.flags == 0x12:  # SYN/ACK
                    print(f"[+] Port {target_port}: OPEN (Received SYN/ACK).")
                    open_ports.append(target_port)
                    if SEND_RST_ON_OPEN:
                        print(f"[*]   Sending RST to {target_ip}:{target_port}...")
                        rst_ip = IP(dst=target_ip, src=actual_source_ip)
                        rst_tcp = TCP(sport=real_source_port, dport=target_port, flags="R", seq=received_tcp.ack)
                        send(rst_ip / rst_tcp, verbose=VERBOSE_SCAPY_SEND_RECV, iface=conf.iface)
                elif received_tcp.flags == 0x14:  # RST/ACK
                    print(f"[-] Port {target_port}: CLOSED (Received RST/ACK).")
                    closed_ports.append(target_port)
                else:
                    print(f"[?] Port {target_port}: FILTERED (Received unexpected TCP flags: {received_tcp.flags:#04x}).")
                    filtered_ports.append(target_port)
            elif response.haslayer(ICMP):
                received_icmp = response.getlayer(ICMP)
                filter_codes = {1, 2, 3, 9, 10, 13}
                if received_icmp.type == 3 and received_icmp.code in filter_codes:
                    print(f"[!] Port {target_port}: FILTERED (Received ICMP Dest Unreachable - Code {received_icmp.code}).")
                    filtered_ports.append(target_port)
                else:
                    print(f"[?] Port {target_port}: Received unexpected ICMP Type={received_icmp.type} Code={received_icmp.code}.")
                    filtered_ports.append(target_port)
            else:
                print(f"[?] Port {target_port}: Received non-TCP/ICMP response?")
                response.show()
                filtered_ports.append(target_port)

        # --- Error Handling ---
        # (Error handling remains largely the same as v2)
        except PermissionError:
             print("[!] FATAL ERROR: Permission denied. Script requires root/administrator privileges.")
             sys.exit(1)
        except OSError as e:
             print(f"[!] FATAL NETWORK ERROR for port {target_port}: {e}")
             sys.exit(1)
        except Exception as e:
            print(f"[!] UNEXPECTED ERROR scanning port {target_port}: {e.__class__.__name__} - {e}")
            if target_port not in filtered_ports:
                 filtered_ports.append(target_port)

    # --- Scan Summary ---
    # (Summary remains the same as v2)
    print("\n" + "="*50)
    print("[*] Scan Complete.")
    print(f"[*] Open ports: {sorted(open_ports) if open_ports else 'None'}")
    print(f"[*] Closed ports: {sorted(closed_ports) if closed_ports else 'None'}")
    print(f"[*] Filtered ports: {sorted(filtered_ports) if filtered_ports else 'None'}")
    print("="*50)
    print("Note: 'Filtered' = No SYN/ACK or RST/ACK received within timeout, or ICMP error.")
    print("      Check firewalls, timeouts, network path. Decoys can sometimes interfere.")
    print("="*50)


# --- Main Execution Guard ---
if __name__ == '__main__':
    # --- Apply Configurations ---
    target_ip_main = DEFAULT_TARGET_IP
    target_ports_main = DEFAULT_TARGET_PORTS
    source_ip_main = DEFAULT_SOURCE_IP
    scan_timeout_main = DEFAULT_TIMEOUT
    min_d_main = MIN_DELAY
    max_d_main = MAX_DELAY
    use_decoys_main = USE_DECOYS
    num_decoys_main = NUM_DECOYS
    # -----------------------------

    # Check privileges
    try:
        if os.geteuid() != 0: raise PermissionError("Requires root")
    except AttributeError: # Windows
        import ctypes
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin(): raise PermissionError("Requires Admin")
        except Exception as e: print(f"[WARN] Admin check failed: {e}")
    except PermissionError as e:
        print(f"[!] Error: {e}. Please run with root/administrator privileges.")
        sys.exit(1)

    # Run Scan
    advanced_syn_scan(target_ip=target_ip_main,
                      target_ports=target_ports_main,
                      source_ip=source_ip_main,
                      timeout=scan_timeout_main,
                      min_delay=min_d_main,
                      max_delay=max_d_main,
                      use_decoys=use_decoys_main,
                      num_decoys=num_decoys_main)
