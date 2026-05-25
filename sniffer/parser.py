import datetime
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP

def parse_packet(packet):
    """
    Parses a Scapy packet into a structured dictionary showing layers,
    source/destination details, hex dump, and printable ASCII payload.
    """
    try:
        # Obtain timestamp
        timestamp = datetime.datetime.fromtimestamp(float(packet.time)).isoformat()
    except Exception:
        timestamp = datetime.datetime.now().isoformat()
    
    # Base structure
    protocol = 'Other'
    src_ip = 'N/A'
    dst_ip = 'N/A'
    src_port = None
    dst_port = None
    length = len(packet)
    info = packet.summary()
    layers = {}
    
    # Layer 2: Ethernet
    if packet.haslayer(Ether):
        eth = packet[Ether]
        layers['Ethernet'] = {
            'src': eth.src,
            'dst': eth.dst,
            'type': hex(eth.type)
        }
        src_ip = eth.src
        dst_ip = eth.dst
        
    # Layer 2.5/3: ARP
    if packet.haslayer(ARP):
        arp = packet[ARP]
        protocol = 'ARP'
        src_ip = arp.psrc
        dst_ip = arp.pdst
        info = f"ARP Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"ARP {arp.psrc} is at {arp.hwsrc}"
        layers['ARP'] = {
            'hwtype': arp.hwtype,
            'ptype': hex(arp.ptype),
            'hwlen': arp.hwlen,
            'plen': arp.plen,
            'op': 'request (1)' if arp.op == 1 else 'reply (2)' if arp.op == 2 else str(arp.op),
            'hwsrc': arp.hwsrc,
            'psrc': arp.psrc,
            'hwdst': arp.hwdst,
            'pdst': arp.pdst
        }
        
    # Layer 3: IPv4
    elif packet.haslayer(IP):
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = 'IPv4'
        layers['IPv4'] = {
            'version': ip.version,
            'ihl': ip.ihl,
            'tos': ip.tos,
            'len': ip.len,
            'id': ip.id,
            'flags': str(ip.flags),
            'frag': ip.frag,
            'ttl': ip.ttl,
            'proto': ip.proto,
            'chksum': hex(ip.chksum) if ip.chksum else '0x0',
            'src': ip.src,
            'dst': ip.dst
        }
        
        # Layer 4: TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            protocol = 'TCP'
            src_port = tcp.sport
            dst_port = tcp.dport
            info = f"TCP: {src_port} -> {dst_port} [{tcp.flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
            layers['TCP'] = {
                'sport': tcp.sport,
                'dport': tcp.dport,
                'seq': tcp.seq,
                'ack': tcp.ack,
                'dataofs': tcp.dataofs,
                'reserved': tcp.reserved,
                'flags': str(tcp.flags),
                'window': tcp.window,
                'chksum': hex(tcp.chksum) if tcp.chksum else '0x0',
                'urgptr': tcp.urgptr
            }
        
        # Layer 4: UDP
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            protocol = 'UDP'
            src_port = udp.sport
            dst_port = udp.dport
            info = f"UDP: {src_port} -> {dst_port} Len={udp.len}"
            layers['UDP'] = {
                'sport': udp.sport,
                'dport': udp.dport,
                'len': udp.len,
                'chksum': hex(udp.chksum) if udp.chksum else '0x0'
            }
            
        # Layer 4: ICMP
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            protocol = 'ICMP'
            info = f"ICMP: {src_ip} -> {dst_ip} Type={icmp.type} Code={icmp.code}"
            layers['ICMP'] = {
                'type': icmp.type,
                'code': icmp.code,
                'chksum': hex(icmp.chksum) if icmp.chksum else '0x0',
                'id': getattr(icmp, 'id', None),
                'seq': getattr(icmp, 'seq', None)
            }
            
    # Layer 3: IPv6
    elif packet.haslayer(IPv6):
        ipv6 = packet[IPv6]
        src_ip = ipv6.src
        dst_ip = ipv6.dst
        protocol = 'IPv6'
        layers['IPv6'] = {
            'version': ipv6.version,
            'tc': ipv6.tc,
            'fl': ipv6.fl,
            'plen': ipv6.plen,
            'nh': ipv6.nh,
            'hlim': ipv6.hlim,
            'src': ipv6.src,
            'dst': ipv6.dst
        }
        
        # Layer 4: TCP on IPv6
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            protocol = 'TCP'
            src_port = tcp.sport
            dst_port = tcp.dport
            info = f"TCP (IPv6): {src_port} -> {dst_port} [{tcp.flags}] Seq={tcp.seq} Ack={tcp.ack}"
            layers['TCP'] = {
                'sport': tcp.sport,
                'dport': tcp.dport,
                'seq': tcp.seq,
                'ack': tcp.ack,
                'flags': str(tcp.flags),
                'window': tcp.window
            }
            
        # Layer 4: UDP on IPv6
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            protocol = 'UDP'
            src_port = udp.sport
            dst_port = udp.dport
            info = f"UDP (IPv6): {src_port} -> {dst_port}"
            layers['UDP'] = {
                'sport': udp.sport,
                'dport': udp.dport,
                'len': udp.len
            }
            
    # Capture raw payload preview
    raw_payload = None
    if packet.haslayer('Raw'):
        raw_bytes = packet['Raw'].load
        hex_preview = " ".join(f"{b:02x}" for b in raw_bytes[:128])
        ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes[:128])
        raw_payload = {
            'hex': hex_preview,
            'ascii': ascii_preview,
            'length': len(raw_bytes)
        }
        
    return {
        'timestamp': timestamp,
        'protocol': protocol,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'length': length,
        'info': info,
        'layers': layers,
        'payload': raw_payload
    }
