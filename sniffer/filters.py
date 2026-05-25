def get_bpf_filter(protocol):
    """
    Translates standard protocol selections to BPF filter strings used by Scapy.
    """
    mapping = {
        'TCP': 'tcp',
        'UDP': 'udp',
        'ICMP': 'icmp',
        'ARP': 'arp',
        'ALL': None
    }
    return mapping.get(protocol.upper(), None)

def filter_packets_list(packets, protocol=None, query=None):
    """
    Filters a list of parsed packet dictionaries based on protocol and query string.
    """
    filtered = packets
    if protocol and protocol.upper() != 'ALL':
        filtered = [p for p in filtered if p['protocol'].upper() == protocol.upper()]
        
    if query:
        q = query.lower()
        filtered = [
            p for p in filtered
            if q in p['src_ip'].lower()
            or q in p['dst_ip'].lower()
            or q in p['info'].lower()
            or (p['src_port'] is not None and q in str(p['src_port']))
            or (p['dst_port'] is not None and q in str(p['dst_port']))
        ]
    return filtered
