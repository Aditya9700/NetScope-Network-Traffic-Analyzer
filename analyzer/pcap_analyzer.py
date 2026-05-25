import os
from scapy.all import PcapReader
from sniffer.parser import parse_packet
from sniffer.statistics import generate_stats

def analyze_pcap(filepath, max_packets=5000):
    """
    Safely parses a PCAP or PCAPNG file, returning a list of parsed packet dictionaries
    and global statistics. Stops processing after max_packets to save memory and CPU.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"PCAP file not found at {filepath}")
        
    packets = []
    try:
        with PcapReader(filepath) as reader:
            for idx, packet in enumerate(reader):
                if idx >= max_packets:
                    break
                try:
                    parsed = parse_packet(packet)
                    parsed['id'] = idx + 1
                    packets.append(parsed)
                except Exception:
                    # Skip corrupt or unreadable packets
                    continue
    except Exception as e:
        raise ValueError(f"Failed parsing PCAP structure: {str(e)}")
        
    stats = generate_stats(packets)
    return {
        'success': True,
        'filename': os.path.basename(filepath),
        'file_size': os.path.getsize(filepath),
        'packets': packets,
        'stats': stats
    }
