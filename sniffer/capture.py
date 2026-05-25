import os
import csv
import threading
import collections
from scapy.all import sniff
from config import Config
from sniffer.parser import parse_packet
from sniffer.statistics import generate_stats

CSV_HEADER = ['timestamp', 'protocol', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'length', 'info']

class LiveCaptureManager:
    """
    Singleton class managing the live Scapy packet capture background thread,
    in-memory thread-safe buffer, and packet CSV logging with log rotation.
    """
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(LiveCaptureManager, cls).__new__(cls)
                cls._instance._init_manager()
            return cls._instance
            
    def _init_manager(self):
        self.packets = collections.deque(maxlen=Config.MAX_BUFFER_SIZE)
        self.lock = threading.Lock()
        self.thread = None
        self.stop_event = threading.Event()
        self.interface = None
        self.filter_str = None
        self.error_message = None
        self.total_captured = 0
        
    def is_running(self):
        return self.thread is not None and self.thread.is_alive()
        
    def start(self, interface=None, filter_str=None):
        with self.lock:
            if self.is_running():
                return False
                
            self.stop_event.clear()
            self.interface = interface
            self.filter_str = filter_str
            self.error_message = None
            
            # Ensure folders exist
            os.makedirs(Config.LOG_FOLDER, exist_ok=True)
            
            # Start sniffer thread
            self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
            self.thread.start()
            return True
            
    def stop(self):
        with self.lock:
            if not self.is_running():
                return False
            self.stop_event.set()
            return True
            
    def _sniff_loop(self):
        while not self.stop_event.is_set():
            try:
                # Sniff packets with a 1-second timeout to allow stop checking
                sniff(
                    prn=self._packet_callback,
                    filter=self.filter_str,
                    iface=self.interface,
                    store=0,
                    timeout=1.0
                )
            except Exception as e:
                self.error_message = str(e)
                break
                
    def _packet_callback(self, packet):
        if self.stop_event.is_set():
            return
            
        try:
            parsed = parse_packet(packet)
            
            with self.lock:
                self.packets.append(parsed)
                self.total_captured += 1
                
            self._log_to_csv(parsed)
        except Exception:
            pass
            
    def _log_to_csv(self, parsed_data):
        filepath = Config.CSV_LOG_PATH
        max_size = Config.MAX_CSV_SIZE_BYTES
        
        # Check size and rotate if needed
        if os.path.exists(filepath) and os.path.getsize(filepath) > max_size:
            self._rotate_logs(filepath)
            
        write_header = not os.path.exists(filepath)
        try:
            with open(filepath, 'a', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=CSV_HEADER, extrasaction='ignore')
                if write_header:
                    writer.writeheader()
                writer.writerow(parsed_data)
        except IOError:
            pass
            
    def _rotate_logs(self, filepath):
        for i in range(5, 0, -1):
            old_file = f"{filepath}.{i}"
            new_file = f"{filepath}.{i+1}"
            if os.path.exists(old_file):
                if os.path.exists(new_file):
                    os.remove(new_file)
                os.rename(old_file, new_file)
        if os.path.exists(filepath):
            os.rename(filepath, f"{filepath}.1")
            
    def get_packets(self, protocol_filter=None, search_query=None, limit=100, offset=0):
        with self.lock:
            # Shallow copy of the list of packets
            packet_list = list(self.packets)
            
        # Apply protocol filter
        if protocol_filter and protocol_filter.upper() != 'ALL':
            packet_list = [p for p in packet_list if p['protocol'].upper() == protocol_filter.upper()]
            
        # Apply keyword/IP search query
        if search_query:
            query = search_query.lower()
            packet_list = [
                p for p in packet_list 
                if query in p['src_ip'].lower() 
                or query in p['dst_ip'].lower() 
                or query in p['info'].lower()
                or (p['src_port'] is not None and query in str(p['src_port']))
                or (p['dst_port'] is not None and query in str(p['dst_port']))
            ]
            
        total = len(packet_list)
        # Sort so that newest packets are listed first
        packet_list.reverse()
        
        paginated = packet_list[offset:offset+limit]
        return paginated, total

    def get_stats(self):
        with self.lock:
            packet_list = list(self.packets)
        stats = generate_stats(packet_list)
        stats['active'] = self.is_running()
        stats['error'] = self.error_message
        stats['total_captured'] = self.total_captured
        return stats

    def clear(self):
        with self.lock:
            self.packets.clear()
            self.total_captured = 0
            if os.path.exists(Config.CSV_LOG_PATH):
                try:
                    os.remove(Config.CSV_LOG_PATH)
                except OSError:
                    pass
