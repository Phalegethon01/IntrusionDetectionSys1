# from scapy.all import sniff
# import threading

# # Global variables to hold the monitoring thread and stop event
# monitoring_thread = None
# stop_event = threading.Event()

# # Define the signatures for different types of attacks
# signatures = [
#     


#     # Malware and Exploits
#     {"name": "Heartbleed Exploit", "pattern": "heartbeat_request"},
#     {"name": "EternalBlue Exploit", "pattern": "SMBv1"},
#     {"name": "Wannacry Ransomware", "pattern": "Wannacry"},
#     {"name": "Mirai Botnet", "pattern": "User-Agent: Mirai"},
#     {"name": "Cryptomining Traffic", "pattern": "stratum+tcp://"},
#     {"name": "Botnet Command & Control", "pattern": "botnet"},
#     {"name": "Ransomware Encryption", "pattern": "RSA public key"},
#     {"name": "Malware Download", "pattern": ".exe download"},
#     {"name": "Spyware Communication", "pattern": "phoning home"},
#     {"name": "Keylogger Traffic", "pattern": "keystrokes"},
#     {"name": "Credential Harvesting", "pattern": "username=password"},
    
#     # Email and Phishing Attacks
#     {"name": "Email Phishing", "pattern": "http://phishing.com"},
#     {"name": "Spear Phishing", "pattern": "Targeted phishing"},
#     {"name": "Malicious Attachment", "pattern": ".exe attachment"},
#     {"name": "Email Spoofing", "pattern": "From: someone@trusted.com"},
#     {"name": "Business Email Compromise (BEC)", "pattern": "urgent wire transfer"},
    
#     # Wireless Attacks
#     {"name": "Rogue Access Point", "pattern": "Unauthorized AP"},
#     {"name": "Deauthentication Attack", "pattern": "Deauth frame"},
#     {"name": "WEP/WPA Cracking", "pattern": "IV replay"},
#     {"name": "Bluetooth Hacking", "pattern": "Bluetooth pin request"},
    
#     # Advanced Persistent Threats (APT)
#     {"name": "APT Lateral Movement", "pattern": "SMB lateral movement"},
#     {"name": "APT Persistence", "pattern": "Scheduled task creation"},
#     {"name": "APT Data Exfiltration", "pattern": "Large outbound data"},
    
#     # Insider Threats
#     {"name": "Data Theft", "pattern": "USB drive activity"},
#     {"name": "Privileged Access Misuse", "pattern": "Accessing critical files"},
    
#     # IoT Attacks
#     {"name": "IoT Device Compromise", "pattern": "default password"},
#     {"name": "IoT Botnet Activity", "pattern": "DDoS from IoT devices"},
    
#     # Social Engineering Attacks
#     {"name": "Watering Hole Attack", "pattern": "Targeted website compromise"},
    
#     # Other
#     {"name": "Generic Anomaly Detection", "pattern": "Unexpected traffic pattern"},
#     {"name": "Suspicious DNS Query", "pattern": "Suspicious domain name"}
# ]

# def match_signature(packet):
#     """
#     Check if the packet matches any predefined signatures.
#     """
#     packet_str = str(packet)
#     for signature in signatures:
#         if signature["pattern"] in packet_str:
#             generate_alert(signature["name"], packet)
#             break

# def generate_alert(signature_name, packet):
#     """
#     Log the detected intrusion.
#     """
#     alert = f"ALERT: {signature_name} detected in packet {packet.summary()}\n"
#     with open("alerts.log", "a") as log_file:
#         log_file.write(alert)
#     print(alert)

# def sniff_packets(ip):
#     """
#     Start sniffing packets for the specified IP address.
#     """
#     print(f"Starting sniffing on IP: {ip}")
#     try:
#         sniff(
#             filter=f"host {ip}",
#             prn=match_signature,
#             store=0,
#             stop_filter=lambda x: stop_event.is_set()  # Stop sniffing if stop_event is set
#         )
#     except Exception as e:
#         print(f"Error during sniffing: {e}")
#     print("Sniffing stopped.")

# def start_ids(ip):
#     """
#     Start the IDS monitoring in a separate thread.
#     """
#     global monitoring_thread, stop_event
#     if monitoring_thread and monitoring_thread.is_alive():
#         print("IDS is already running. Stopping it first.")
#         stop_ids()
    
#     stop_event.clear()  # Reset the stop event
#     monitoring_thread = threading.Thread(target=sniff_packets, args=(ip,), daemon=True)
#     monitoring_thread.start()  # Start monitoring in a background thread
#     print("IDS started.")



# def stop_ids():
#     """
#     Stop the IDS monitoring.
#     """
#     global monitoring_thread, stop_event
#     if monitoring_thread and monitoring_thread.is_alive():
#         print("Stopping IDS...")  # Log the stop attempt
#         stop_event.set()  # Signal the thread to stop
#         # monitoring_thread.join()  # Do not wait for the thread to finish
#         monitoring_thread = None  # Clean up the thread reference
#         print("IDS stop signal sent successfully.")
#     else:
#         print("No IDS is running.")

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import threading

monitoring_thread = None
stop_event = threading.Event()

# Example signature patterns (as you provided)
signatures = [
    # Web Application Attacks
    {"name": "SQL Injection Attempt", "pattern": "' OR '1'='1"},
    {"name": "SQL Injection Using UNION", "pattern": "UNION SELECT"},
    {"name": "Cross-Site Scripting (XSS)", "pattern": "<script>"},
    {"name": "Blind SQL Injection", "pattern": "SLEEP(5)"},
    {"name": "Remote File Inclusion (RFI)", "pattern": "http://"},
    {"name": "Local File Inclusion (LFI)", "pattern": "../"},
    {"name": "Command Injection", "pattern": "; ls"},
    {"name": "Directory Traversal Attack", "pattern": "/etc/passwd"},
    {"name": "HTTP Flood (DDoS)", "pattern": "GET / HTTP/1.1"},
    {"name": "Slowloris Attack", "pattern": "Connection: keep-alive"},
    {"name": "Shellshock Bash Exploit", "pattern": "() { :; };"},
    {"name": "Web Shell Detection", "pattern": "cmd=cat /etc/passwd"},
    
    # Network Attacks
    {"name": "SSH Brute Force Attack", "pattern": "Failed password for"},
    {"name": "FTP Brute Force Attack", "pattern": "530 Login incorrect"},
    {"name": "DNS Amplification Attack", "pattern": "ANY"},
    {"name": "ARP Spoofing", "pattern": "ARP reply is-at"},
    {"name": "SMB Relay Attack", "pattern": "NTLMSSP"},
    {"name": "ICMP Flood (Ping of Death)", "pattern": "Type 8 Code 0"},
    {"name": "SYN Flood", "pattern": "SYN"},
    {"name": "UDP Flood", "pattern": "UDP"},
    {"name": "TCP FIN Scan", "pattern": "FIN"},
    {"name": "TCP Xmas Scan", "pattern": "FIN, PSH, URG"},
    {"name": "TCP Null Scan", "pattern": "NULL"},
    {"name": "DNS Tunneling", "pattern": "TXT"},
    {"name": "IPv6 Routing Header Attack", "pattern": "Routing Header"},
    {"name": "IP Fragmentation Attack", "pattern": "IP fragments"},
    {"name": "Port Scan", "pattern": "SYN to multiple ports"},
    {"name": "Tor Exit Node Traffic", "pattern": "User-Agent: Tor"},
    
    
]

# Function to log detected intrusions
def log_alert(alert):
    with open("alerts.log", "a") as log_file:
        log_file.write(f"{datetime.now()} - {alert}\n")

# Function to match signatures against packet data
def check_for_signatures(packet):
    if packet.haslayer(Raw):  # Check packet payload (HTTP, etc.)
        payload = packet[Raw].load.decode(errors="ignore")  # Decode payload
        for signature in signatures:
            if signature["pattern"] in payload:
                alert = f"{signature['name']} Detected from {packet[IP].src} to {packet[IP].dst}"
                log_alert(alert)
                print(alert)  # Optional: print to terminal for real-time alerts
                return

    # Handle specific network-based signatures
    if packet.haslayer(TCP):
        if packet[TCP].flags == "S":  # SYN scan (Porvleat scan)
            alert = f"SYN Scan Detected from {packet[IP].src} to {packet[IP].dst}"
            log_alert(alert)
            print(alert)
    
    if packet.haslayer(ICMP):
        if packet[ICMP].type == 8 and packet[ICMP].code == 0:  # Ping request (ICMP Flood)
            alert = f"ICMP Flood Detected from {packet[IP].src} to {packet[IP].dst}"
            log_alert(alert)
            print(alert)

    # Add more checks for your other network attack signatures...
            # Detect Null Scan (no flags set)
            # Detect TCP Xmas Scan (FIN, PSH, URG flags set)
    if packet[TCP].flags == 'FPU':
        alert = f"TCP Xmas Scan Detected from {packet[IP].src} to {packet[IP].dst}"
        log_alert(alert)
        print(alert)


    if packet[TCP].flags == 0:
        alert = f"TCP Null Scan Detected from {packet[IP].src} to {packet[IP].dst}"
        log_alert(alert)
        print(alert)

    if packet.haslayer(UDP) and packet.haslayer(Raw):
        if b"ANY" in packet[Raw].load:
            alert = f"DNS Amplification Attack Detected from {packet[IP].src} to {packet[IP].dst}"
            log_alert(alert)
            print(alert)

    # Detect ARP Spoofing
    if packet.haslayer('ARP') and packet.op == 2:  # ARP reply
        alert = f"ARP Spoofing Detected from {packet[IP].src} to {packet[IP].dst}"
        log_alert(alert)
        print(alert)


# Function to capture packets on the network
def packet_callback(packet):
    if packet.haslayer(IP):
        check_for_signatures(packet)

# Function to start IDS monitoring on a specified IP address
# def start_ids(target_ip):
#     print(f"Starting IDS for IP: {target_ip}")
#     sniff(filter=f"ip host {target_ip}", prn=packet_callback, store=0)

# # Function to stop IDS (optional, depending on how you implement it)
# def stop_ids():
#     global monitoring_thread, stop_event
#     if monitoring_thread and monitoring_thread.is_alive():
#         print("Stopping IDS...")  # Log the stop attempt
#         stop_event.set()  # Signal the thread to stop
#         # monitoring_thread.join()  # Do not wait for the thread to finish
#         monitoring_thread = None  # Clean up the thread reference
#         print("IDS stop signal sent successfully.")
#     else:
#         print("No IDS is running.")



def start_ids(target_ip):
    global monitoring_thread, stop_event
    stop_event.clear()  # Reset the stop event
    print(f"Starting IDS for IP: {target_ip}")
    monitoring_thread = threading.Thread(target=sniff_packets, args=(target_ip,))
    monitoring_thread.start()

def sniff_packets(target_ip):
    sniff(filter=f"ip host {target_ip}", prn=packet_callback, store=0, stop_filter=lambda x: stop_event.is_set())

# Function to stop IDS monitoring
def stop_ids():
    global monitoring_thread, stop_event
    if monitoring_thread and monitoring_thread.is_alive():
        print("Stopping IDS...")
        stop_event.set()  # Signal the thread to stop
        monitoring_thread.join()  # Wait for the thread to finish
        monitoring_thread = None  # Clean up the thread reference
        print("IDS stopped successfully.")
    else:
        print("No IDS is running.")



