import collections
from datetime import datetime

def generate_stats(packets):
    """
    Computes network metrics and statistics from a list of parsed packet dictionaries.
    """
    total = len(packets)
    if total == 0:
        return {
            'total_packets': 0,
            'protocol_counts': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0},
            'protocol_percentages': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0},
            'top_sources': [],
            'top_destinations': [],
            'top_ports': [],
            'avg_packet_size': 0,
            'packet_rate': 0,
            'data_volume_bytes': 0,
            'data_rate_kbps': 0
        }

    # Extract protocol counts
    protocol_counts = collections.Counter(p['protocol'] for p in packets)
    for proto in ['TCP', 'UDP', 'ICMP', 'ARP', 'Other']:
        if proto not in protocol_counts:
            protocol_counts[proto] = 0

    protocol_percentages = {
        proto: round((count / total) * 100, 2)
        for proto, count in protocol_counts.items()
    }

    # Count top IP addresses (filter out non-IPs like MAC address placeholders)
    sources = [p['src_ip'] for p in packets if p['src_ip'] not in ('N/A', 'None')]
    destinations = [p['dst_ip'] for p in packets if p['dst_ip'] not in ('N/A', 'None')]
    
    top_sources = collections.Counter(sources).most_common(5)
    top_destinations = collections.Counter(destinations).most_common(5)

    # Collect source and destination ports
    ports = []
    for p in packets:
        if p['src_port'] is not None:
            ports.append(p['src_port'])
        if p['dst_port'] is not None:
            ports.append(p['dst_port'])
            
    top_ports = collections.Counter(ports).most_common(5)

    data_volume_bytes = sum(p['length'] for p in packets)
    avg_packet_size = round(data_volume_bytes / total, 2)

    # Calculate packet transmission and data rates
    packet_rate = 0
    data_rate_kbps = 0
    if total > 1:
        try:
            timestamps = []
            for p in packets:
                try:
                    timestamps.append(datetime.fromisoformat(p['timestamp']))
                except ValueError:
                    # Ignore ill-formatted datetime strings if any
                    continue
            
            if len(timestamps) > 1:
                timestamps = sorted(timestamps)
                duration = (timestamps[-1] - timestamps[0]).total_seconds()
                if duration > 0:
                    packet_rate = round(total / duration, 2)
                    data_rate_kbps = round((data_volume_bytes * 8) / (duration * 1000), 2)
        except Exception:
            pass

    return {
        'total_packets': total,
        'protocol_counts': dict(protocol_counts),
        'protocol_percentages': protocol_percentages,
        'top_sources': [{'ip': ip, 'count': count} for ip, count in top_sources],
        'top_destinations': [{'ip': ip, 'count': count} for ip, count in top_destinations],
        'top_ports': [{'port': port, 'count': count} for port, count in top_ports],
        'avg_packet_size': avg_packet_size,
        'packet_rate': packet_rate,
        'data_volume_bytes': data_volume_bytes,
        'data_rate_kbps': data_rate_kbps
    }
