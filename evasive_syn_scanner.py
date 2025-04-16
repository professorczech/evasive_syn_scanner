#!/usr/bin/env python3
"""
Enhanced SYN Packet Scanner with Evasion Techniques using Scapy (v2)

This script performs a SYN scan incorporating techniques to potentially
reduce detectability by basic IDS, Firewalls, and Honeypots.
Version 2 prioritizes reliability by disabling fragmentation by default,
as fragmentation often causes open ports to appear filtered.

Techniques Implemented:
  - Random Source Ports
  - Variable Timing Delays
  - IP Fragmentation (Optional, Disabled by Default)
  - Basic TCP Options
  - Target Port Randomization

WARNING: Educational purposes ONLY. Unauthorized scanning is illegal.
         Requires root/administrator privileges.
"""
import sys
import random
import time
import os # Added for geteuid check

# Attempt to import Scapy components
try:
    # Import specific functions for clarity
    from scapy.all import IP, TCP, ICMP, sr1, send, fragment, conf
    # Suppress Scapy's verbose output unless needed
    conf.verb = 0
    # Optionally disable IPv6 layers if causing issues or not needed
    # conf.ipv6_enabled = False
except ImportError:
    print("[!] Error: Scapy library not found or import failed.")
    print("Please install Scapy: pip install scapy")
    sys.exit(1)
except Exception as e:
    print(f"[!] Error importing Scapy or setting conf: {e}")
    sys.exit(1)


# --- Configuration ---
DEFAULT_TARGET_IP = "192.168.100.101" # Default Victim IP

# Updated list including common ports and the specified open lab ports
DEFAULT_TARGET_PORTS = [
    80, 22, 443, 21, 23, 25, 110, 139, 445, 3389, # Common
    1443, # Common Alt HTTPS
    2222, 2323, 2121, 1389, 1445, 1137 # Specified Lab Ports (Note: 1445 duplicated)
]
# Remove duplicates just in case
DEFAULT_TARGET_PORTS = sorted(list(set(DEFAULT_TARGET_PORTS)))

DEFAULT_SOURCE_IP = None # Let Scapy/OS choose source IP by default
# Increased timeout slightly for potentially better reliability
DEFAULT_TIMEOUT = 2.5
MIN_DELAY = 0.5        # Minimum delay between probes (in seconds)
MAX_DELAY = 1.5        # Maximum delay between probes (adjusted)

# --- Fragmentation Settings ---
# Fragmentation is often unreliable and can cause open ports to appear filtered.
# Disabled by default for better scan accuracy. Enable for specific evasion tests.
USE_FRAGMENTATION = False # <<<=== Disabled by Default
FRAGMENT_SIZE = 8       # Use standard minimum fragment size (multiple of 8) if re-enabled

# --- Other Settings ---
RANDOMIZE_PORTS = True # Set to True to scan ports in random order
SEND_RST_ON_OPEN = True # Send RST packet if SYN/ACK is received
VERBOSE_SCAPY_SEND_RECV = False # Set True for detailed Scapy send/recv logs

# --- Evasion Functions ---

def get_random_source_port():
    """Returns a random ephemeral port number."""
    return random.randint(1025, 65535)

def add_basic_tcp_options(tcp_layer):
    """Adds a common TCP option (MSS)."""
    # Keep it simple; complex options might cause issues or be fingerprinted.
    tcp_options = [('MSS', 1460)]
    tcp_layer.options = tcp_options
    return tcp_layer

# --- Core Scan Function ---

def evasive_syn_scan(target_ip, target_ports, source_ip=None, timeout=DEFAULT_TIMEOUT,
                     min_delay=MIN_DELAY, max_delay=MAX_DELAY, use_fragmentation=USE_FRAGMENTATION,
                     frag_size=FRAGMENT_SIZE):
    """
    Performs an evasive SYN scan on the specified target ports.

    Args:
        target_ip (str): The target IP address.
        target_ports (list): A list of integers representing ports to scan.
        source_ip (str, optional): The source IP address to use. Defaults to None.
        timeout (float): Timeout in seconds to wait for a response.
        min_delay (float): Minimum delay between probes.
        max_delay (float): Maximum delay between probes.
        use_fragmentation (bool): Whether to use IP fragmentation.
        frag_size (int): Payload size for IP fragments if use_fragmentation is True.
    """
    open_ports = []
    closed_ports = []
    filtered_ports = []

    # Validate frag_size if using fragmentation
    if use_fragmentation and frag_size % 8 != 0:
         print(f"[WARN] Fragment size {frag_size} is not a multiple of 8. Adjusting to {frag_size - (frag_size % 8)}")
         frag_size = frag_size - (frag_size % 8)
         if frag_size <= 0:
             print("[WARN] Adjusted fragment size is <= 0. Disabling fragmentation.")
             use_fragmentation = False

    scan_ports = list(target_ports)
    if RANDOMIZE_PORTS:
        print("[*] Randomizing target port order.")
        random.shuffle(scan_ports)

    print(f"[*] Starting evasive SYN scan against {target_ip}...")
    print(f"[*] Ports to scan ({len(scan_ports)}): {scan_ports}")
    print(f"[*] Options: Timeout={timeout}s, Delay={min_delay:.1f}-{max_delay:.1f}s, Fragmentation={use_fragmentation}, FragSize={frag_size if use_fragmentation else 'N/A'}")

    for target_port in scan_ports:
        response = None
        delay = random.uniform(min_delay, max_delay)
        print(f"[*] Port {target_port}: Waiting {delay:.2f} seconds...")
        time.sleep(delay)

        # Craft the packet
        source_port = get_random_source_port()
        ip_layer = IP(dst=target_ip)
        if source_ip:
            ip_layer.src = source_ip

        tcp_layer = TCP(sport=source_port, dport=target_port, flags="S")
        tcp_layer = add_basic_tcp_options(tcp_layer) # Add TCP options
        base_packet = ip_layer / tcp_layer

        print(f"[*] Port {target_port}: Sending SYN from sport {source_port}")

        try:
            # --- Send Packet ---
            if use_fragmentation:
                print(f"[*]   Using IP fragmentation (fragsize={frag_size})...")
                frags = fragment(base_packet, fragsize=frag_size)
                # Send first fragment and wait for potential reply
                response = sr1(frags[0], timeout=timeout, verbose=VERBOSE_SCAPY_SEND_RECV, iface=conf.iface) # Specify interface if needed
                # Send remaining fragments without waiting (best effort)
                # Note: Target needs all fragments for reassembly before potentially replying SYN/ACK.
                # This is why fragmentation often leads to 'filtered' results even on open ports.
                for frag in frags[1:]:
                    send(frag, verbose=VERBOSE_SCAPY_SEND_RECV, iface=conf.iface)
            else:
                # Send the packet whole
                response = sr1(base_packet, timeout=timeout, verbose=VERBOSE_SCAPY_SEND_RECV, iface=conf.iface) # Specify interface if needed

            # --- Analyze Response ---
            if response is None:
                # No response within timeout
                print(f"[!] Port {target_port}: FILTERED (No response received).")
                print("    (Check network path, firewalls on sender/receiver, or try increasing timeout.)")
                if use_fragmentation:
                     print("    (Fragmentation is enabled; this often causes timeouts on open ports. Try disabling it.)")
                filtered_ports.append(target_port)

            elif response.haslayer(TCP):
                received_tcp = response.getlayer(TCP)
                # Check if the response is for our probe (match ACK number)
                # Scapy's sr1 handles basic request/reply matching, but double-check flags
                if received_tcp.flags == 0x12:  # SYN/ACK
                    print(f"[+] Port {target_port}: OPEN (Received SYN/ACK).")
                    open_ports.append(target_port)
                    if SEND_RST_ON_OPEN:
                        # Send RST to close the connection cleanly
                        print(f"[*]   Sending RST to {target_ip}:{target_port}...")
                        rst_ip = IP(dst=target_ip, src=ip_layer.src) # Use actual source IP used
                        rst_tcp = TCP(sport=source_port, dport=target_port, flags="R", seq=received_tcp.ack)
                        send(rst_ip / rst_tcp, verbose=VERBOSE_SCAPY_SEND_RECV, iface=conf.iface)

                elif received_tcp.flags == 0x14:  # RST/ACK
                    print(f"[-] Port {target_port}: CLOSED (Received RST/ACK).")
                    closed_ports.append(target_port)
                else:
                    # Received unexpected TCP flags
                    print(f"[?] Port {target_port}: FILTERED (Received unexpected TCP flags: {received_tcp.flags:#04x}).")
                    filtered_ports.append(target_port)

            elif response.haslayer(ICMP):
                received_icmp = response.getlayer(ICMP)
                # Check for ICMP Destination Unreachable messages indicating filtering
                # Type 3, Codes: 1 (Host Unreachable), 2 (Proto Unreachable), 3 (Port Unreachable),
                # 9 (Comm Prohibited), 10 (Host Prohibited), 13 (Comm Admin Prohibited)
                filter_codes = {1, 2, 3, 9, 10, 13}
                if received_icmp.type == 3 and received_icmp.code in filter_codes:
                    print(f"[!] Port {target_port}: FILTERED (Received ICMP Dest Unreachable - Code {received_icmp.code}).")
                    filtered_ports.append(target_port)
                else:
                    # Other ICMP messages received
                    print(f"[?] Port {target_port}: Received unexpected ICMP Type={received_icmp.type} Code={received_icmp.code}.")
                    response.show() # Show details for unexpected ICMP
                    filtered_ports.append(target_port) # Classify as filtered/unknown

            else:
                # Received something else entirely (shouldn't happen often for SYN scan)
                print(f"[?] Port {target_port}: Received non-TCP/ICMP response?")
                response.show()
                filtered_ports.append(target_port) # Classify as filtered/unknown

        except PermissionError:
            print("[!] FATAL ERROR: Permission denied. Script requires root/administrator privileges.")
            sys.exit(1)
        except OSError as e:
             # Catch errors like "Network is unreachable" if interface is down/wrong
             print(f"[!] FATAL NETWORK ERROR for port {target_port}: {e}")
             print("[!] Check network connectivity, interface name (Scapy's conf.iface), and permissions.")
             sys.exit(1)
        except Exception as e:
            print(f"[!] UNEXPECTED ERROR scanning port {target_port}: {e.__class__.__name__} - {e}")
            if target_port not in filtered_ports:
                 filtered_ports.append(target_port)


    # --- Scan Summary ---
    print("\n" + "="*50)
    print("[*] Scan Complete.")
    print(f"[*] Open ports: {sorted(open_ports) if open_ports else 'None'}")
    print(f"[*] Closed ports: {sorted(closed_ports) if closed_ports else 'None'}")
    print(f"[*] Filtered ports (No Response / ICMP Error / Other): {sorted(filtered_ports) if filtered_ports else 'None'}")
    print("="*50)
    print("Note: 'Filtered' means no SYN/ACK or RST/ACK was received.")
    print("      This could be due to firewalls, packet loss, short timeouts,")
    print("      or issues with fragmentation if it was enabled.")
    print("="*50)

# --- Main Execution Guard ---
if __name__ == '__main__':
    # Configuration overrides can be placed here if needed
    target_ip_main = DEFAULT_TARGET_IP
    target_ports_main = DEFAULT_TARGET_PORTS
    source_ip_main = DEFAULT_SOURCE_IP
    use_frag_main = USE_FRAGMENTATION
    frag_size_main = FRAGMENT_SIZE
    scan_timeout_main = DEFAULT_TIMEOUT
    min_d_main = MIN_DELAY
    max_d_main = MAX_DELAY

    # Check for root privileges
    try:
        if os.geteuid() != 0:
           print("[!] Error: Script requires root privileges.")
           sys.exit(1)
    except AttributeError: # geteuid() not on Windows
        # Basic check, might need refinement
        import ctypes
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] Error: Script requires Administrator privileges on Windows.")
                sys.exit(1)
        except Exception as e:
            print(f"[WARN] Could not check for Admin privileges on Windows: {e}")

    # Run the scan
    evasive_syn_scan(target_ip=target_ip_main,
                     target_ports=target_ports_main,
                     source_ip=source_ip_main,
                     timeout=scan_timeout_main,
                     min_delay=min_d_main,
                     max_delay=max_d_main,
                     use_fragmentation=use_frag_main,
                     frag_size=frag_size_main)
