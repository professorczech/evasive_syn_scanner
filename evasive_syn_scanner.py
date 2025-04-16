#!/usr/bin/env python3
"""
Enhanced SYN Packet Scanner with Evasion Techniques using Scapy

This script performs a SYN scan incorporating techniques to potentially
reduce detectability by basic IDS, Firewalls, and Honeypots.

Techniques Implemented:
  - Random Source Ports: Avoids simple source-port based blocking.
  - Variable Timing: Introduces random delays between probes.
  - IP Fragmentation (Optional): Attempts to bypass basic packet filters.
  - Basic TCP Options: Adds common options (MSS, NOP, Window Scale).
  - Target Port Randomization: Scans ports in a non-sequential order.

WARNING: This script is for educational purposes and authorized testing ONLY.
         Unauthorized scanning is illegal and unethical.
         Evasion is not guaranteed against modern security systems.
         Requires root/administrator privileges to run.
"""
import sys
import random
import time
import os # Added for geteuid check

# Attempt to import Scapy components. If your IDE shows errors here,
# ensure Scapy is installed in the correct environment and the IDE points to it.
try:
    from scapy.all import IP, TCP, sr1, send, fragment, conf
    # Suppress unwanted Scapy IPv6 warnings if they appear
    conf.ipv6_enabled = False
    # Suppress verbose output during packet sending/receiving unless desired
    conf.verb = 0
except ImportError:
    print("[!] Error: Scapy library not found or import failed.")
    print("Please install Scapy: pip install scapy")
    print("Ensure your IDE is using the correct Python interpreter.")
    sys.exit(1)


# --- Configuration ---
DEFAULT_TARGET_IP = "192.168.100.101" # Default Victim IP
DEFAULT_TARGET_PORTS = [80, 22, 443, 21, 23, 25, 110, 139, 445, 3389, 1443] # Common ports to scan
DEFAULT_SOURCE_IP = None # Let Scapy/OS choose source IP by default
DEFAULT_TIMEOUT = 1.5    # Reduced timeout for faster scanning, increase if needed
MIN_DELAY = 0.5        # Minimum delay between probes (in seconds)
MAX_DELAY = 2.0        # Maximum delay between probes (in seconds)
USE_FRAGMENTATION = True # Set to True to enable IP fragmentation
FRAGMENT_SIZE = 16     # IP fragment payload size (small for testing evasion)
RANDOMIZE_PORTS = True # Set to True to scan ports in random order
VERBOSE_SCAPY_SEND_RECV = False # Set to True to see Scapy's send/receive messages (overrides conf.verb for sr1/send)

# --- Evasion Functions ---

def get_random_source_port():
    """Returns a random ephemeral port number."""
    return random.randint(1025, 65535)

def add_basic_tcp_options(tcp_layer):
    """Adds some common TCP options to the layer."""
    # Example: MSS (Maximum Segment Size), NOP (No-Operation), Window Scale
    # Note: Values are illustrative. Real systems negotiate these.
    # Using WScale=10 requires TCP SACK permitted option (kind 4, length 2) often precedes it.
    # Let's keep it simpler for now, as complex options might also be fingerprinted.
    tcp_options = [('MSS', 1460)] # Just MSS is very common
    # tcp_options = [('MSS', 1460), ('NOP', None), ('WScale', 10), ('SAckOK', b'')] # More complex example
    tcp_layer.options = tcp_options
    return tcp_layer

# --- Core Scan Function ---

def evasive_syn_scan(target_ip, target_ports, source_ip=None, timeout=DEFAULT_TIMEOUT,
                     min_delay=MIN_DELAY, max_delay=MAX_DELAY, use_fragmentation=USE_FRAGMENTATION,
                     frag_size=FRAGMENT_SIZE): # Added frag_size parameter
    """
    Performs an evasive SYN scan on the specified target ports.

    Args:
        target_ip (str): The target IP address.
        target_ports (list): A list of integers representing ports to scan.
        source_ip (str, optional): The source IP address to use. Defaults to None (OS default).
        timeout (int): Timeout in seconds to wait for a response.
        min_delay (float): Minimum delay between probes.
        max_delay (float): Maximum delay between probes.
        use_fragmentation (bool): Whether to use IP fragmentation for the SYN packet.
        frag_size (int): Payload size for IP fragments if use_fragmentation is True.
    """
    open_ports = []
    closed_ports = []
    filtered_ports = []

    scan_ports = list(target_ports) # Create a mutable copy
    if RANDOMIZE_PORTS:
        print("[*] Randomizing target port order.")
        random.shuffle(scan_ports)

    print(f"[*] Starting evasive SYN scan against {target_ip}...")
    print(f"[*] Ports to scan: {scan_ports}")
    print(f"[*] Options: Random Src Port=True, Delay={min_delay:.1f}-{max_delay:.1f}s, Fragmentation={use_fragmentation}, FragSize={frag_size if use_fragmentation else 'N/A'}")

    for target_port in scan_ports:
        # Initialize response variable for this iteration (Addresses Linter Warning 8)
        response = None

        # Introduce random delay before sending the next probe
        delay = random.uniform(min_delay, max_delay)
        # time.sleep(delay) # Line 175: time.sleep() accepts float, IDE warning is likely spurious
        print(f"[*] Port {target_port}: Waiting for {delay:.2f} seconds...")
        time.sleep(float(delay)) # Explicitly casting to float, though unnecessary

        # Craft the packet
        ip_layer = IP(dst=target_ip)
        if source_ip:
            ip_layer.src = source_ip

        source_port = get_random_source_port()
        tcp_layer = TCP(sport=source_port, dport=target_port, flags="S")
        tcp_layer = add_basic_tcp_options(tcp_layer) # Add TCP options

        base_packet = ip_layer / tcp_layer

        print(f"[*] Port {target_port}: Sending SYN from sport {source_port}")

        try:
            if use_fragmentation:
                # Fragment the packet. sr1 might only capture reply to first fragment.
                # Note: Fragmentation effectiveness varies and can be detected.
                print(f"[*] Port {target_port}: Using IP fragmentation (fragsize={frag_size}).")
                # 'fragsize' is the correct Scapy parameter (Addresses Linter Warning 9)
                frags = fragment(base_packet, fragsize=frag_size)
                # Send first fragment and wait for reply
                response = sr1(frags[0], timeout=timeout, verbose=VERBOSE_SCAPY_SEND_RECV)
                # Send remaining fragments without waiting for replies here
                for frag in frags[1:]:
                    send(frag, verbose=VERBOSE_SCAPY_SEND_RECV)
            else:
                # Send the packet whole
                response = sr1(base_packet, timeout=timeout, verbose=VERBOSE_SCAPY_SEND_RECV)

            # Analyze the response
            if response is None:
                print(f"[!] Port {target_port}: No response from {target_ip}. Port might be FILTERED or host down.")
                filtered_ports.append(target_port)
            # Check if the response packet (response[0]) has a TCP layer
            elif response.haslayer(TCP):
                 # Access the TCP layer from the received packet
                received_tcp = response.getlayer(TCP)
                if received_tcp.flags == 0x12:  # SYN/ACK (18)
                    print(f"[+] Port {target_port}: OPEN on {target_ip} (received SYN/ACK).")
                    open_ports.append(target_port)
                    # Send RST to cleanly close the connection attempt initiated by SYN/ACK
                    print(f"[*] Port {target_port}: Sending RST to close connection.")
                    # Ensure RST uses correct source IP if specified
                    rst_ip = IP(dst=target_ip, src=source_ip) if source_ip else IP(dst=target_ip)
                    # Use the same source port Scapy received the reply on (which matches our random source_port)
                    # Use seq=ack from SYN/ACK per TCP spec for RST
                    rst_tcp = TCP(sport=source_port, dport=target_port, flags="R", seq=received_tcp.ack)
                    send(rst_ip / rst_tcp, verbose=VERBOSE_SCAPY_SEND_RECV)
                elif received_tcp.flags == 0x14:  # RST/ACK (20)
                    print(f"[-] Port {target_port}: CLOSED on {target_ip} (received RST/ACK).")
                    closed_ports.append(target_port)
                else:
                    print(f"[?] Port {target_port}: Received unexpected TCP flags: {received_tcp.flags:#04x}. Possibly FILTERED or unusual state.")
                    filtered_ports.append(target_port) # Treat unexpected flags as potentially filtered
            # Check if the response packet has an ICMP layer (e.g., Destination Unreachable)
            elif response.haslayer("ICMP"):
                received_icmp = response.getlayer("ICMP")
                # ICMP type 3 (Destination Unreachable) codes 1, 2, 3, 9, 10, 13 often indicate filtering
                filter_codes = {1, 2, 3, 9, 10, 13}
                if received_icmp.type == 3 and received_icmp.code in filter_codes:
                    print(f"[!] Port {target_port}: FILTERED on {target_ip} (received ICMP Dest Unreachable - code {received_icmp.code}).")
                    filtered_ports.append(target_port)
                else:
                    print(f"[?] Port {target_port}: Received ICMP response Type={received_icmp.type} Code={received_icmp.code}. Summary:")
                    response.summary() # Show summary for unexpected ICMP
                    filtered_ports.append(target_port) # Treat unexpected ICMP as filtered/unknown
            else:
                # E.g., Other protocols? Unlikely for a TCP scan response.
                print(f"[?] Port {target_port}: Received non-TCP/ICMP response. Summary:")
                response.summary()
                filtered_ports.append(target_port) # Treat as filtered/unknown


        except PermissionError:
            print("[!] Error: Permission denied. This script requires root/administrator privileges.")
            print("       Please run using 'sudo python3 evasive_syn_scanner.py'")
            sys.exit(1)
        except Exception as e:
            print(f"[!] An error occurred scanning port {target_port}: {e}")
            # Add to filtered as the state is unknown due to error
            if target_port not in filtered_ports: # Avoid duplicates if already added
                 filtered_ports.append(target_port)


    print("\n[*] Scan Complete.")
    print(f"[*] Open ports: {sorted(open_ports) if open_ports else 'None'}")
    print(f"[*] Closed ports: {sorted(closed_ports) if closed_ports else 'None'}")
    print(f"[*] Filtered/Unknown ports: {sorted(filtered_ports) if filtered_ports else 'None'}")

# --- Main Execution ---
if __name__ == '__main__':
    # --- Customizable Parameters ---
    # Use different variable names to avoid shadowing function parameters (Addresses Linter Warnings 5, 6, 7)
    target_ip_main = DEFAULT_TARGET_IP
    target_ports_main = DEFAULT_TARGET_PORTS
    source_ip_main = DEFAULT_SOURCE_IP # Optional: Specify your source IP if needed, otherwise leave as None
    use_frag_main = USE_FRAGMENTATION
    frag_size_main = FRAGMENT_SIZE
    scan_timeout_main = DEFAULT_TIMEOUT
    min_d_main = MIN_DELAY
    max_d_main = MAX_DELAY
    # -----------------------------

    # Check for root privileges (needed for raw socket access) more reliably
    try:
        # Check effective user ID, works on POSIX systems (Linux/macOS)
        if os.geteuid() != 0:
           print("[!] Error: This script requires root/administrator privileges to run.")
           print("       Please run using 'sudo python3 evasive_syn_scanner.py'")
           sys.exit(1)
    except AttributeError:
        # os.geteuid() doesn't exist on Windows, check for admin rights differently
        # This is a basic check, might need ctypes for a more robust Windows check
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("[!] Error: This script requires administrator privileges to run on Windows.")
                print("       Please run from an Administrator Command Prompt/PowerShell.")
                sys.exit(1)
        except Exception as e:
            print(f"[!] Warning: Could not reliably check for administrator privileges on Windows: {e}")
            print("         Attempting to proceed, but may fail due to permissions.")


    # Run the scan
    evasive_syn_scan(target_ip_main, target_ports_main, source_ip=source_ip_main,
                     timeout=scan_timeout_main, min_delay=min_d_main, max_delay=max_d_main,
                     use_fragmentation=use_frag_main, frag_size=frag_size_main)