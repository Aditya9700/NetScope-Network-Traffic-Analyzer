import os
from flask import Blueprint, jsonify, request
from werkzeug.utils import secure_filename
from config import Config
from sniffer.capture import LiveCaptureManager
from sniffer.filters import get_bpf_filter
from sniffer.statistics import generate_stats
from analyzer.pcap_analyzer import analyze_pcap
from analyzer.traffic_analyzer import analyze_traffic_history
from scapy.all import conf

api_bp = Blueprint('api', __name__)
capture_manager = LiveCaptureManager()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

def validate_pcap_magic(filepath):
    """
    Validates magic bytes to ensure file is a true PCAP/PCAPNG capture.
    - PCAP (Big Endian): A1 B2 C3 D4
    - PCAP (Little Endian): D4 C3 B2 A1
    - PCAPNG: 0A 0D 0D 0A
    """
    try:
        with open(filepath, 'rb') as f:
            header = f.read(4)
            if len(header) < 4:
                return False
            # Check PCAP
            if header in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'):
                return True
            # Check PCAPNG
            if header == b'\x0a\x0d\x0d\x0a':
                return True
        return False
    except Exception:
        return False

@api_bp.route('/interfaces', methods=['GET'])
def get_interfaces():
    """Returns available local network interfaces."""
    interfaces = []
    try:
        # Loop through Scapy's loaded interfaces
        for key in conf.ifaces:
            iface = conf.ifaces[key]
            interfaces.append({
                'id': str(key),
                'name': str(iface.name),
                'description': str(iface.description or iface.name),
                'ip': str(iface.ip or 'No IP')
            })
    except Exception as e:
        return jsonify({'error': 'Failed to load interfaces', 'details': str(e)}), 500
        
    return jsonify(interfaces)

@api_bp.route('/capture/status', methods=['GET'])
def get_capture_status():
    """Checks the running status of the live sniffer."""
    return jsonify({
        'running': capture_manager.is_running(),
        'interface': capture_manager.interface,
        'filter': capture_manager.filter_str,
        'total_captured': capture_manager.total_captured,
        'error': capture_manager.error_message
    })

@api_bp.route('/capture/start', methods=['POST'])
def start_capture():
    """Starts the background sniffer thread on a designated interface and filter."""
    data = request.json or {}
    interface_id = data.get('interface')
    protocol = data.get('protocol', 'ALL')
    
    # Translate UI Protocol selection to BPF Filter string
    bpf_filter = get_bpf_filter(protocol)
    
    # Resolve interface name/id from scapy configurations
    selected_iface = None
    if interface_id:
        try:
            # Try to match by key or by interface name
            if interface_id in conf.ifaces:
                selected_iface = conf.ifaces[interface_id]
            else:
                for key in conf.ifaces:
                    if conf.ifaces[key].name == interface_id:
                        selected_iface = conf.ifaces[key]
                        break
        except Exception:
            selected_iface = interface_id
            
    success = capture_manager.start(interface=selected_iface, filter_str=bpf_filter)
    if success:
        return jsonify({'message': 'Live capture started successfully.'})
    else:
        return jsonify({'error': 'Sniffer is already running or failed to start.'}), 400

@api_bp.route('/capture/stop', methods=['POST'])
def stop_capture():
    """Stops the live sniffer background execution."""
    success = capture_manager.stop()
    if success:
        return jsonify({'message': 'Live capture stopped.'})
    else:
        return jsonify({'message': 'Sniffer was not active.'}), 400

@api_bp.route('/capture/clear', methods=['POST'])
def clear_capture():
    """Clears the live buffer and removes runtime packets.csv log."""
    capture_manager.clear()
    return jsonify({'message': 'Memory buffer and packet logs cleared.'})

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    """Retrieves live packet capture metrics."""
    return jsonify(capture_manager.get_stats())

@api_bp.route('/packets', methods=['GET'])
def get_packets():
    """Retrieves captured packets list with support for paging and filters."""
    protocol = request.args.get('protocol', 'ALL')
    search = request.args.get('search', '')
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    packets, total = capture_manager.get_packets(
        protocol_filter=protocol,
        search_query=search,
        limit=limit,
        offset=offset
    )
    
    return jsonify({
        'packets': packets,
        'total': total,
        'limit': limit,
        'offset': offset
    })

@api_bp.route('/protocols', methods=['GET'])
def get_protocols():
    """Retrieves live protocol distribution percentages."""
    stats = capture_manager.get_stats()
    return jsonify(stats['protocol_percentages'])

@api_bp.route('/top-ips', methods=['GET'])
def get_top_ips():
    """Retrieves top transmitting and receiving IP addresses."""
    stats = capture_manager.get_stats()
    return jsonify({
        'sources': stats['top_sources'],
        'destinations': stats['top_destinations']
    })

@api_bp.route('/top-ports', methods=['GET'])
def get_top_ports():
    """Retrieves top destination/source port frequency count."""
    stats = capture_manager.get_stats()
    return jsonify(stats['top_ports'])

@api_bp.route('/upload', methods=['POST'])
def upload_pcap():
    """Handles secure PCAP/PCAPNG file upload and returns comprehensive statistics."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file element in the request.'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file.'}), 400
        
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file extension. Only .pcap and .pcapng are allowed.'}), 400
        
    # Secure filename
    filename = secure_filename(file.filename)
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    filepath = os.path.join(Config.UPLOAD_FOLDER, filename)
    
    try:
        # Save file to disk
        file.save(filepath)
        
        # Verify Magic bytes for security
        if not validate_pcap_magic(filepath):
            # Delete file
            os.remove(filepath)
            return jsonify({'error': 'Security check failed: File header does not match a valid PCAP format.'}), 400
            
        # Parse PCAP structure
        analysis_data = analyze_pcap(filepath, max_packets=5000)
        
        # Parse advanced metrics using Pandas/NumPy
        advanced_metrics = analyze_traffic_history(analysis_data['packets'])
        
        # Delete the uploaded file after processing to maintain cleanliness
        os.remove(filepath)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'file_size': analysis_data['file_size'],
            'stats': analysis_data['stats'],
            'advanced': advanced_metrics,
            # Limit packets sent in JSON to avoid UI bottleneck
            'packets': analysis_data['packets'][:1000] 
        })
    except Exception as e:
        # Clean up file in case of failure
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': 'PCAP processing failed.', 'details': str(e)}), 500
