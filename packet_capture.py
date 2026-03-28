import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import time
import pandas as pd
import numpy as np
import threading
from datetime import datetime

# --- PACKET STAT COUNTS ---
packet_history = []
active_connections = {}

def get_protocol_name(proto):
    """Maps protocol numbers to KDD labels."""
    if proto == 6: return 'tcp'
    elif proto == 17: return 'udp'
    elif proto == 1: return 'icmp'
    return 'other'

def get_service_name(port):
    """Simple port to service mapping."""
    services = {80: 'http', 443: 'http', 21: 'ftp', 22: 'ssh', 23: 'telnet', 53: 'dns'}
    return services.get(port, 'other')

def process_packet(packet):
    """Extracts features from a single packet."""
    global packet_history, active_connections
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = get_protocol_name(packet[IP].proto)
        size = len(packet)
        timestamp = time.time()
        
        # Determine TCP/UDP specifics
        src_port = 0
        dst_port = 0
        flag = 'SF' # Default to success
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            if 'S' in flags and 'A' not in flags: flag = 'S0' # Connection attempt
            elif 'R' in flags: flag = 'REJ' # Rejected
            
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
        # Store for session analysis (mocking time-based features)
        packet_info = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'size': size,
            'flag': flag,
            'timestamp': timestamp,
            'service': get_service_name(dst_port)
        }
        
        packet_history.append(packet_info)
        # Keep recent history small for performance
        if len(packet_history) > 1000:
            packet_history.pop(0)

def extract_kdd_features(src_ip):
    """Transforms packet history into a KDD-compatible feature vector (41 features)."""
    global packet_history
    
    # Filter by source IP
    ip_pkts = [p for p in packet_history if p['src_ip'] == src_ip]
    if not ip_pkts:
        return None
    
    latest = ip_pkts[-1]
    
    # Feature engineering for KDD (Simplified for demo)
    # KDD columns: duration, protocol_type, service, flag, src_bytes, dst_bytes, etc.
    
    features = {
        'duration': round(time.time() - latest['timestamp'], 2),
        'protocol_type': latest['protocol'],
        'service': latest['service'],
        'flag': latest['flag'],
        'src_bytes': sum(p['size'] for p in ip_pkts[-10:]), # Rolling last 10
        'dst_bytes': 0, # Hard to track without full duplex capture
        'land': 1 if latest['src_ip'] == latest['dst_ip'] else 0,
        'wrong_fragment': 0,
        'urgent': 0,
        'hot': 0,
        'num_failed_logins': 0,
        'logged_in': 0,
        'num_compromised': 0,
        'root_shell': 0,
        'su_attempted': 0,
        'num_root': 0,
        'num_file_creations': 0,
        'num_shells': 0,
        'num_access_files': 0,
        'num_outbound_cmds': 0,
        'is_host_login': 0,
        'is_guest_login': 0,
        'count': len(ip_pkts), # Num of connections to same host in last 2 seconds (simulated)
        'srv_count': len([p for p in ip_pkts if p['service'] == latest['service']]),
        'serror_rate': 0.0,
        'srv_serror_rate': 0.0,
        'rerror_rate': 0.0,
        'srv_rerror_rate': 0.0,
        'same_srv_rate': 1.0,
        'diff_srv_rate': 0.0,
        'srv_diff_host_rate': 0.0,
        'dst_host_count': len(packet_history),
        'dst_host_srv_count': len([p for p in packet_history if p['service'] == latest['service']]),
        'dst_host_same_srv_rate': 1.0,
        'dst_host_diff_srv_rate': 0.0,
        'dst_host_same_src_port_rate': 1.0,
        'dst_host_srv_diff_host_rate': 0.0,
        'dst_host_serror_rate': 0.0,
        'dst_host_srv_serror_rate': 0.0,
        'dst_host_rerror_rate': 0.0,
        'dst_host_srv_rerror_rate': 0.0
    }
    
    return features

def start_sniffing(interface=None):
    """Starts packet capture in a background thread."""
    print(f"[SYSTEM] Starting LIVE network sniffing on {interface or 'default interface'}...")
    sniff_thread = threading.Thread(target=lambda: scapy.sniff(iface=interface, prn=process_packet, store=0))
    sniff_thread.daemon = True
    sniff_thread.start()

if __name__ == "__main__":
    start_sniffing()
    while True:
        time.sleep(2)
        feat = extract_kdd_features('127.0.0.1')
        if feat:
            print(f"Captured Features: {feat['src_bytes']} bytes from local.")
