# flow_extractor.py - Enhanced with real 5-tuple extraction

import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
from tqdm import tqdm
import os 

TARGET_FEATURES = 78

def safe_div(a, b):
    """Safe division avoiding div by zero"""
    return a / b if b != 0 else 0

def pcap_to_flows_with_metadata(pcap_path: str):
    """
    Extract CICIDS2017-compatible features + 5-tuple metadata
    Returns: (DataFrame with 78 features, List of 5-tuple dicts)
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(pcap_path)

    packets = rdpcap(pcap_path)
    if len(packets) == 0:
        return pd.DataFrame(), []

    # Group packets into flows with metadata
    flows = defaultdict(lambda: {
        'packets': [],
        'fwd_packets': [],
        'bwd_packets': [],
        'timestamps': [],
        'fwd_timestamps': [],
        'bwd_timestamps': [],
        'src_ip': None,
        'dst_ip': None,
        'src_port': 0,
        'dst_port': 0,
        'protocol': 'OTHER'
    })
    
    for pkt in tqdm(packets, desc="Grouping packets", leave=False, disable=len(packets) > 5000):
        if IP not in pkt:
            continue
        
        ip = pkt[IP]
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
        src = ip.src
        dst = ip.dst
        sport = int(pkt[TCP].sport) if TCP in pkt else int(pkt[UDP].sport) if UDP in pkt else 0
        dport = int(pkt[TCP].dport) if TCP in pkt else int(pkt[UDP].dport) if UDP in pkt else 0
        
        # Create bidirectional flow key
        if (src, sport) < (dst, dport):
            key = (src, dst, sport, dport, proto)
            is_forward = True
        else:
            key = (dst, src, dport, sport, proto)
            is_forward = False
        
        flow = flows[key]
        
        # Store 5-tuple metadata (only once per flow)
        if flow['src_ip'] is None:
            flow['src_ip'] = key[0]
            flow['dst_ip'] = key[1]
            flow['src_port'] = key[2]
            flow['dst_port'] = key[3]
            flow['protocol'] = key[4]
        
        flow['packets'].append(pkt)
        flow['timestamps'].append(float(pkt.time))
        
        if is_forward:
            flow['fwd_packets'].append(pkt)
            flow['fwd_timestamps'].append(float(pkt.time))
        else:
            flow['bwd_packets'].append(pkt)
            flow['bwd_timestamps'].append(float(pkt.time))

    # Extract features and metadata for each flow
    feature_rows = []
    metadata_list = []
    
    for key, flow_data in tqdm(flows.items(), desc="Extracting features", leave=False, disable=len(flows) > 1000):
        dst_ip = flow_data["dst_ip"]
        if dst_ip.startswith(("224.", "239.", "255.")):
            continue
        
        features = extract_cicids_features(flow_data, key)
        feature_rows.append(features)
        
        # Store 5-tuple metadata
        metadata = {
            'src_ip': flow_data['src_ip'],
            'dst_ip': flow_data['dst_ip'],
            'src_port': flow_data['src_port'],
            'dst_port': flow_data['dst_port'],
            'protocol': flow_data['protocol'],
            'packet_count': len(flow_data['packets']),
            'byte_count': sum(len(p) for p in flow_data['packets']),
            'duration': flow_data['timestamps'][-1] - flow_data['timestamps'][0] if len(flow_data['timestamps']) > 1 else 0
        }
        metadata_list.append(metadata)

    df = pd.DataFrame(feature_rows)
    df.fillna(0.0, inplace=True)
 
    
    # Ensure exactly 78 features
    if df.shape[1] < TARGET_FEATURES:
        for i in range(TARGET_FEATURES - df.shape[1]):
            df[f'placeholder_{i}'] = 0.0
    elif df.shape[1] > TARGET_FEATURES:
        df = df.iloc[:, :TARGET_FEATURES]
    
    return df, metadata_list

def extract_cicids_features(flow_data, flow_key):
    """Extract 78 CICIDS2017 features from flow data"""
    
    pkts = flow_data['packets']
    fwd_pkts = flow_data['fwd_packets']
    bwd_pkts = flow_data['bwd_packets']
    times = np.array(flow_data['timestamps'])
    fwd_times = np.array(flow_data['fwd_timestamps'])
    bwd_times = np.array(flow_data['bwd_timestamps'])
    
    # Packet sizes
    sizes = np.array([len(p) for p in pkts], dtype=np.float64)
    fwd_sizes = np.array([len(p) for p in fwd_pkts], dtype=np.float64)
    bwd_sizes = np.array([len(p) for p in bwd_pkts], dtype=np.float64)
    
    # Header lengths (estimate: 20 bytes IP + 20 bytes TCP/UDP)
    header_len = 40
    fwd_payload_sizes = np.maximum(fwd_sizes - header_len, 0)
    bwd_payload_sizes = np.maximum(bwd_sizes - header_len, 0)
    
    # Inter-arrival times
    iats = np.diff(times) if len(times) > 1 else np.array([0.0])
    fwd_iats = np.diff(fwd_times) if len(fwd_times) > 1 else np.array([0.0])
    bwd_iats = np.diff(bwd_times) if len(bwd_times) > 1 else np.array([0.0])
    
    # Duration
    duration = times[-1] - times[0] if len(times) > 1 else 0.0
    
    # TCP flags (if TCP)
    tcp_flags = {'FIN': 0, 'SYN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0, 'URG': 0, 'ECE': 0, 'CWR': 0}
    fwd_tcp_flags = {'PSH': 0, 'URG': 0}
    bwd_tcp_flags = {'PSH': 0, 'URG': 0}
    
    if flow_key[4] == "TCP":
        for p in pkts:
            if TCP in p:
                flags = int(p[TCP].flags)
                tcp_flags['FIN'] += (flags & 0x01) != 0
                tcp_flags['SYN'] += (flags & 0x02) != 0
                tcp_flags['RST'] += (flags & 0x04) != 0
                tcp_flags['PSH'] += (flags & 0x08) != 0
                tcp_flags['ACK'] += (flags & 0x10) != 0
                tcp_flags['URG'] += (flags & 0x20) != 0
                tcp_flags['ECE'] += (flags & 0x40) != 0
                tcp_flags['CWR'] += (flags & 0x80) != 0
        
        for p in fwd_pkts:
            if TCP in p:
                flags = int(p[TCP].flags)
                fwd_tcp_flags['PSH'] += (flags & 0x08) != 0
                fwd_tcp_flags['URG'] += (flags & 0x20) != 0
        
        for p in bwd_pkts:
            if TCP in p:
                flags = int(p[TCP].flags)
                bwd_tcp_flags['PSH'] += (flags & 0x08) != 0
                bwd_tcp_flags['URG'] += (flags & 0x20) != 0
    
    # Calculate features (78 total) - same as before
    features = [
        duration,
        len(pkts),
        np.sum(sizes),
        safe_div(np.sum(sizes), duration) if duration > 0 else 0,
        safe_div(len(pkts), duration) if duration > 0 else 0,
        np.mean(iats) if len(iats) > 0 else 0,
        np.std(iats) if len(iats) > 1 else 0,
        len(fwd_pkts),
        np.sum(fwd_sizes),
        np.mean(fwd_sizes) if len(fwd_sizes) > 0 else 0,
        np.std(fwd_sizes) if len(fwd_sizes) > 1 else 0,
        np.max(fwd_sizes) if len(fwd_sizes) > 0 else 0,
        np.min(fwd_sizes) if len(fwd_sizes) > 0 else 0,
        safe_div(np.sum(fwd_sizes), duration) if duration > 0 else 0,
        len(bwd_pkts),
        np.sum(bwd_sizes),
        np.mean(bwd_sizes) if len(bwd_sizes) > 0 else 0,
        np.std(bwd_sizes) if len(bwd_sizes) > 1 else 0,
        np.max(bwd_sizes) if len(bwd_sizes) > 0 else 0,
        np.min(bwd_sizes) if len(bwd_sizes) > 0 else 0,
        safe_div(np.sum(bwd_sizes), duration) if duration > 0 else 0,
        np.mean(fwd_iats) if len(fwd_iats) > 0 else 0,
        np.std(fwd_iats) if len(fwd_iats) > 1 else 0,
        np.max(fwd_iats) if len(fwd_iats) > 0 else 0,
        np.min(fwd_iats) if len(fwd_iats) > 0 else 0,
        np.sum(fwd_iats) if len(fwd_iats) > 0 else 0,
        np.mean(fwd_iats**2) if len(fwd_iats) > 0 else 0,
        np.std(fwd_iats**2) if len(fwd_iats) > 1 else 0,
        np.mean(bwd_iats) if len(bwd_iats) > 0 else 0,
        np.std(bwd_iats) if len(bwd_iats) > 1 else 0,
        np.max(bwd_iats) if len(bwd_iats) > 0 else 0,
        np.min(bwd_iats) if len(bwd_iats) > 0 else 0,
        np.sum(bwd_iats) if len(bwd_iats) > 0 else 0,
        np.mean(bwd_iats**2) if len(bwd_iats) > 0 else 0,
        np.std(bwd_iats**2) if len(bwd_iats) > 1 else 0,
        tcp_flags['FIN'],
        tcp_flags['SYN'],
        tcp_flags['RST'],
        tcp_flags['PSH'],
        tcp_flags['ACK'],
        tcp_flags['URG'],
        tcp_flags['ECE'],
        tcp_flags['CWR'],
        fwd_tcp_flags['PSH'],
        bwd_tcp_flags['PSH'],
        fwd_tcp_flags['URG'],
        bwd_tcp_flags['URG'],
        np.sum(fwd_payload_sizes),
        np.sum(bwd_payload_sizes),
        np.mean(fwd_payload_sizes) if len(fwd_payload_sizes) > 0 else 0,
        np.mean(bwd_payload_sizes) if len(bwd_payload_sizes) > 0 else 0,
        np.std(fwd_payload_sizes) if len(fwd_payload_sizes) > 1 else 0,
        np.std(bwd_payload_sizes) if len(bwd_payload_sizes) > 1 else 0,
        safe_div(len(fwd_pkts), len(pkts)) if len(pkts) > 0 else 0,
        np.mean(sizes) if len(sizes) > 0 else 0,
        np.std(sizes) if len(sizes) > 1 else 0,
        np.var(sizes) if len(sizes) > 1 else 0,
        np.max(sizes) if len(sizes) > 0 else 0,
        np.min(sizes) if len(sizes) > 0 else 0,
        np.percentile(sizes, 25) if len(sizes) > 0 else 0,
        np.percentile(sizes, 75) if len(sizes) > 0 else 0,
        np.max(iats) if len(iats) > 0 else 0,
        np.min(iats) if len(iats) > 0 else 0,
        np.sum(iats) if len(iats) > 0 else 0,
        safe_div(duration, len(pkts)) if len(pkts) > 0 else 0,
        np.std(iats) if len(iats) > 1 else 0,
        np.max(iats) if len(iats) > 0 else 0,
        np.min(iats) if len(iats) > 0 else 0,
        safe_div(len(pkts), duration) if duration > 0 else 0,
        safe_div(np.sum(sizes), duration) if duration > 0 else 0,
        safe_div(np.sum(fwd_sizes), len(fwd_pkts)) if len(fwd_pkts) > 0 else 0,
        safe_div(np.sum(bwd_sizes), len(bwd_pkts)) if len(bwd_pkts) > 0 else 0,
        len(fwd_pkts) / max(len(bwd_pkts), 1),
        np.sum(fwd_sizes) / max(np.sum(bwd_sizes), 1),
        1 if flow_key[4] == "TCP" else 0,
        1 if flow_key[4] == "UDP" else 0,
        safe_div(tcp_flags['SYN'], len(pkts)) if len(pkts) > 0 else 0,
        safe_div(tcp_flags['ACK'], len(pkts)) if len(pkts) > 0 else 0,
    ]
    
    return features

# Backward compatibility
def pcap_to_flows(pcap_path):
    """Legacy function - returns only DataFrame"""
    df, _ = pcap_to_flows_with_metadata(pcap_path)
    return df

if __name__ == "__main__":
    import sys, os
    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]
        print(f"Testing feature extraction on: {pcap_path}")
        df, metadata = pcap_to_flows_with_metadata(pcap_path)
        print(f"\nExtracted {len(df)} flows with {df.shape[1]} features")
        print(f"\nSample metadata:")
        for i, meta in enumerate(metadata[:3]):
            print(f"  Flow {i+1}: {meta['src_ip']}:{meta['src_port']} → {meta['dst_ip']}:{meta['dst_port']} ({meta['protocol']})")