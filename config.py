import os

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'netscope_secure_secret_key_1337')
    
    # Absolute paths
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    
    # Upload configuration
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB limit
    ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}
    
    # Live sniffer buffer & log configuration
    LOG_FOLDER = os.path.join(BASE_DIR, 'logs')
    CSV_LOG_PATH = os.path.join(LOG_FOLDER, 'packets.csv')
    MAX_CSV_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB log rotation trigger
    MAX_BUFFER_SIZE = 2000  # Max packets to keep in memory
    
    # Default sniffer configuration
    DEFAULT_INTERFACE = None  # None selects default scapy interface
