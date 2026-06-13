# NetScope – Network Traffic Analyzer
Live Deployment: https://netscope-network-traffic-analyzer.onrender.com/

NetScope is a production-ready, multithreaded network traffic analysis platform designed to capture, parse, and visualize live or offline packets. Built using Python, Scapy, Flask, Pandas, and Chart.js, the system decapsulates Layer 2, 3, and 4 protocols (Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP), logs data streams to rotated CSV archives, and serves telemetry statistics over a modern glassmorphism web dashboard.

This project is built to demonstrate software engineering best practices, network stack comprehension, asynchronous backend processing, and analytical system design tailored for enterprise software and systems engineering roles.

---

## Technical Architecture & Flow

NetScope uses a decoupled, concurrent architecture to isolate low-level network interface bindings from REST interface consumers:

```
                  +-----------------------------------+
                  | Network Interface Card (NIC)      |
                  +-----------------+-----------------+
                                    | Raw Sockets
                                    v [Asynchronous Sniff Thread]
                  +-----------------------------------+
                  | Scapy Ingestion Engine (Capture)  |
                  +-----------------+-----------------+
                                    |
                                    v
                  +-----------------------------------+
                  | Header Decapsulation Parser       |
                  +--------+-----------------+--------+
                           |                 |
            InMemory Deque |                 | Stream Log
            (Buffer Lock)  v                 v (Log Rotation)
                  +-----------------+      +-----------------+
                  | Collections.     |      | rotated         |
                  | deque (2k limit) |      | packets.csv     |
                  +--------+--------+      +-----------------+
                           |
                           v [WSGI Server Endpoint Queries]
                  +-----------------------------------+
                  | Flask Web REST API Gateway        |
                  +--------+-----------------+--------+
                           |                 |
            NumPy Stats &  |                 | Parsed Packets
            Pandas Resamplev                 v JSON Stream
                  +-----------------------------------+
                  | Chart.js Dynamic Canvas UI        |
                  +-----------------------------------+
```

1. **Packet Ingestion Layer:** An asynchronous thread binds Scapy sniff loops to active network sockets. It implements a non-blocking poll design that intercepts frames without dropping packets.
2. **Decapsulation Parser:** Extracts nested structures. It parses Ethernet frames, maps protocol fields, processes TCP flags and sequence variables, and generates ASCII/Hex payloads.
3. **Thread-Safe Buffer:** Captures are routed to a circular, memory-capped queue `collections.deque` protected by thread synchronization primitives (`threading.Lock`).
4. **Log Rotation Engine:** Concurrently writes packets to a persistent `packets.csv`. It rotates files at a 5MB size limit to prevent buffer overflows or disk leakage.
5. **REST API Gateway:** Employs modular Flask blueprints. It validates input queries and enforces secure file parsing boundaries.
6. **Data Science Aggregator:** Utilizes Pandas and NumPy to compute standard deviations and percentiles of packet sizes, resample traffic timeline arrays, and build communication matrices.
7. **Telemetry UI:** Chart.js polls endpoints to dynamically update pie charts, bandwidth lines, and IP bar graphs.

---

## Core Features

- **Live Capture & Decoding:** Captures TCP, UDP, ICMP, and ARP packets. Displays source/destination ports, sequence numbers, and payload previews.
- **Deep Packet Inspection (DPI):** Tabbed tree panel in the UI allows clicking any packet to inspect field headers layer-by-layer (Ethernet, IPv4/IPv6, Layer 4 protocol structures).
- **Advanced PCAP Upload Parser:** Drag-and-drop `.pcap` or `.pcapng` files. Validates magic bytes (signatures) to secure against mime-type spoofing.
- **Real-Time Data Telemetry:** Live updating charts (Chart.js) showing protocol breakdowns, bandwidth timeline rates, top IP addresses, and active ports.
- **Micro-Throughput Stats:** Tracks packet transmission rate (p/s) and bitrates (Kbps) using Pandas time-series resampling.
- **Security-First Boundary Design:** Implements upload boundaries (16MB max), Werkzeug secure filename filters, and payload size limitations to prevent DoS vector exploits.

---

## Folder Structure

```
NetScope/
├── app.py                      # Flask Server Entry point
├── config.py                   # Global system parameters
├── requirements.txt            # System dependencies
├── README.md                   # Project documentation
├── .gitignore                  # Git untracked rule bindings
├── render.yaml                 # Render cloud hosting spec
│
├── sniffer/                    # Packet sniffing modules
│   ├── __init__.py
│   ├── capture.py              # Thread-safe background sniffer singleton
│   ├── parser.py               # Layer decapsulator & Hex previewer
│   ├── filters.py              # UI to Scapy BPF filter compiler
│   └── statistics.py           # Real-time metrics aggregator
│
├── analyzer/                   # Offline file parsing modules
│   ├── __init__.py
│   ├── pcap_analyzer.py        # Stream-based PCAP parser
│   └── traffic_analyzer.py     # NumPy/Pandas data analytics
│
├── api/                        # Route controllers
│   ├── __init__.py
│   └── routes.py               # REST endpoints blueprint
│
├── logs/                       # Rotated CSV stream logging folder
│
├── uploads/                    # Temporary PCAP upload buffer folder
│
├── templates/                  # Glassmorphism views
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   ├── upload.html
│   ├── statistics.html
│   └── about.html
│
└── static/                     # Assets & scripts
    ├── css/
    │   └── style.css           # Modern theme styling & protocol sign-offs
    └── js/
        └── dashboard.js        # Polling loops, Canvas triggers, drag-drop
```

---

## Installation & Local Setup

### 1. Prerequisites

- **Python 3.10+**
- **Npcap / WinPcap (Windows)**
  > [!IMPORTANT]
  > On **Windows**, Scapy requires Npcap to bind to raw network sockets. Download and install Npcap from [npcap.com](https://npcap.com/) (ensure "Install Npcap in WinPcap API-compatible Mode" is selected).
  > On **Linux/macOS**, install `libpcap` via package managers (`sudo apt install libpcap-dev`).

### 2. Configure Virtual Environment & Dependencies

Clone the project, navigate to the `NetScope` directory, create a virtual environment, and install dependencies:

```bash
# Navigate to directory
cd NetScope

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On macOS/Linux:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 3. Execution

Live packet sniffing requires administrative/root privileges to access the network card.

**On Windows (Run as Administrator):**
Open your terminal (CMD or PowerShell) as Administrator, activate the virtual environment, and run:
```bash
python app.py
```

**On Linux / macOS:**
```bash
sudo ./venv/bin/python app.py
```

Access the dashboard at `http://127.0.0.1:5000`.

---

## REST API Documentation

| Endpoint | Method | Description | Request / Query Params | Response Format (JSON) |
| :--- | :--- | :--- | :--- | :--- |
| `/api/interfaces` | `GET` | Lists local interfaces | None | `[ { "id": "1", "name": "Wi-Fi", ... } ]` |
| `/api/capture/status` | `GET` | Checks sniffer thread state | None | `{ "running": true, "interface": "Wi-Fi" }` |
| `/api/capture/start` | `POST` | Activates bg capture thread | `{"interface": "id", "protocol": "ALL"}` | `{"message": "Capture started"}` |
| `/api/capture/stop` | `POST` | Stops bg capture thread | None | `{"message": "Capture stopped"}` |
| `/api/capture/clear` | `POST` | Resets buffers & deletes logs | None | `{"message": "Logs cleared"}` |
| `/api/stats` | `GET` | Pulls aggregated capture stats | None | `{ "total_captured": 102, "avg_packet_size": 250, ... }` |
| `/api/packets` | `GET` | Streams buffer packets | `?protocol=TCP&search=192&limit=50` | `{ "packets": [...], "total": 12 }` |
| `/api/upload` | `POST` | PCAP upload analysis | Multipart form file field: `file` | `{ "success": true, "stats": {...}, "packets": [...] }` |

---


