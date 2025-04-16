# Enhanced SYN Scanner with Evasion Techniques

## Description

This Python script utilizes the Scapy library to perform SYN scans against specified targets and ports. It incorporates several techniques aimed at reducing the likelihood of detection by basic Intrusion Detection Systems (IDS), Firewalls, and Honeypots compared to a standard, naive SYN scan.

**⚠️ Disclaimer:** This script is intended strictly for **educational purposes** and for use in **controlled laboratory environments** where you have explicit permission to test. Running scans against networks or systems without authorization is **illegal and unethical**. The evasion techniques implemented here are **not foolproof** and may still be detected by modern, sophisticated security systems (NGFW, IPS, advanced honeypots). Use responsibly and ethically.

## Features

* **SYN Scan:** Performs the classic "half-open" scan to identify open TCP ports.
* **Random Source Ports:** Uses a different, random source port (from the ephemeral range) for each probe, making it harder to block based on a single source port.
* **Variable Timing (Throttling):** Introduces randomized delays between sending packets, disrupting rhythmic patterns that signature-based IDS might look for.
* **IP Fragmentation (Optional):** Splits the outgoing SYN packet into smaller IP fragments. This *may* bypass very simple packet filters or IDS engines that do not properly reassemble or inspect fragmented traffic. *Note: Fragmentation itself can be a detection flag for some systems, and effectiveness varies greatly.*
* **Basic TCP Options:** Adds common TCP options (MSS, Window Scale) to the SYN packet to make it appear slightly more similar to legitimate traffic.
* **Target Port Randomization:** Scans the specified target ports in a random order instead of sequentially.
* **Clean Session Termination:** Sends a RST packet upon receiving a SYN/ACK to properly tear down the initiated connection attempt.

## Requirements

* **Python 3:** The script is written for Python 3.x.
* **Scapy:** The powerful packet manipulation library. Install using pip:
    ```bash
    pip install scapy
    ```
* **Root/Administrator Privileges:** Raw socket access, necessary for crafting and sending packets with Scapy, requires elevated privileges. Run the script using `sudo`:
    ```bash
    sudo python3 evasive_syn_scanner.py
    ```

## Usage

1.  **Configure Parameters:** Modify the variables in the `--- Configuration ---` section or within the `if __name__ == '__main__':` block of the script (`evasive_syn_scanner.py`):
    * `DEFAULT_TARGET_IP`: The IP address of the system you want to scan.
    * `DEFAULT_TARGET_PORTS`: A list of TCP ports to scan.
    * `DEFAULT_SOURCE_IP`: Optionally set a specific source IP address (default is `None`, letting the OS choose).
    * `DEFAULT_TIMEOUT`: How long (in seconds) to wait for a reply for each port.
    * `MIN_DELAY` / `MAX_DELAY`: The minimum and maximum delay (in seconds) randomly chosen between sending probes. Increase these values for a stealthier (but slower) scan.
    * `USE_FRAGMENTATION`: Set to `True` to enable IP fragmentation, `False` to disable.
    * `RANDOMIZE_PORTS`: Set to `True` to scan ports randomly, `False` for sequential scanning.
    * `VERBOSE_SCAPY`: Set to `True` if you want Scapy's detailed send/receive output (can be noisy).

2.  **Run the Script:** Execute the script with root/administrator privileges:
    ```bash
    sudo python3 evasive_syn_scanner.py
    ```

3.  **Interpret Output:** The script will print its actions and the results:
    * `[+] Port X is OPEN`: Received a SYN/ACK response.
    * `[-] Port X is CLOSED`: Received a RST/ACK response.
    * `[!] No response... Port might be filtered`: No reply received within the timeout. Could be due to a firewall dropping the packet, the packet getting lost, or the host being down.
    * `[?] Received unexpected flags/non-TCP response`: Indicates an unusual reply, often implying filtering or a non-standard host response.

## How Evasion Techniques Work (Simplified)

* **Random Source Ports:** Prevents simple firewall rules that might block a single source port making too many connections quickly.
* **Variable Timing:** Makes the scan traffic less uniform and predictable, potentially avoiding detection based on consistent inter-packet timing.
* **IP Fragmentation:** A packet filter might only inspect the first fragment (which may lack full header info) or might not reassemble fragments correctly, potentially allowing the fragmented SYN through. *Caveat: Many systems handle fragmentation correctly or flag it.*
* **TCP Options:** Makes the packet slightly more complex, potentially passing basic checks looking for overly simple packets.
* **Port Randomization:** Avoids sequential port scanning patterns easily detected by IDS.

## Limitations and Detection

* **Stateful Firewalls/IPS:** These systems track connection states. While a SYN scan doesn't complete the handshake, multiple SYN packets (even fragmented or timed out) to various ports from one source IP are still highly suspicious and easily detectable.
* **Behavioral Analysis:** Modern systems look for patterns characteristic of scanning (e.g., one host contacting many ports on another host quickly, even with delays).
* **Honeypots:** Designed to be scanned. They might intentionally respond slowly, emulate vulnerabilities, or log connection attempts extensively, easily identifying scan activity regardless of these basic evasion techniques.
* **Fragmentation Detection:** Fragmentation itself can be logged or trigger alerts. Some systems drop fragments or have stricter rules for them.
* **Rate Limiting:** Firewalls/IPS can limit connection attempts per source IP over time, negating simple timing variations if the overall rate is still high.
* **Log Correlation:** Centralized logging (SIEM) can correlate seemingly disparate probes over longer times or across multiple targets.

**In summary, while these techniques add layers over a basic scan, they are unlikely to bypass robust, modern network security defenses.** True evasion often requires much more sophisticated methods, adapting dynamically to the target environment, and often using distributed sources.