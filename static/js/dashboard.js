/**
 * NetScope Telemetry & Control Engine
 * Vanilla JS integrating Chart.js, HTML5 Drag & Drop, AJAX Polling and Tabbed Inspectors.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Global Constants & State
    const POLL_INTERVAL_MS = 1500;
    let pollIntervalId = null;
    let liveCharts = {};
    let selectedPacketData = null;

    // Chart.js Color Mapping
    const PROTOCOL_COLORS = {
        'TCP': '#ef4444',
        'UDP': '#3b82f6',
        'ICMP': '#f59e0b',
        'ARP': '#10b981',
        'Other': '#6b7280'
    };

    // Shared UI Elements
    const themeToggleBtn = document.getElementById('theme-toggle-btn');
    const activeInterfaceLabel = document.getElementById('active-interface-label');
    const globalLiveDot = document.getElementById('global-live-dot');
    const globalStatusText = document.getElementById('global-status-text');

    /* ----------------------------------------------------
       Theme Toggle Mechanism
    ------------------------------------------------------- */
    function initTheme() {
        const storedTheme = localStorage.getItem('theme') || 'dark';
        document.documentElement.setAttribute('data-theme', storedTheme);
        updateThemeToggleIcon(storedTheme);
    }

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeToggleIcon(newTheme);
        });
    }

    function updateThemeToggleIcon(theme) {
        if (!themeToggleBtn) return;
        const icon = themeToggleBtn.querySelector('i');
        if (theme === 'dark') {
            icon.className = 'fa-solid fa-sun';
            themeToggleBtn.title = 'Switch to Light Mode';
        } else {
            icon.className = 'fa-solid fa-moon';
            themeToggleBtn.title = 'Switch to Dark Mode';
        }
    }

    initTheme();

    /* ----------------------------------------------------
       Global Live Status Indicator Poller
    ------------------------------------------------------- */
    function pollGlobalStatus() {
        fetch('/api/capture/status')
            .then(res => res.json())
            .then(status => {
                if (status.running) {
                    globalLiveDot.className = 'live-dot active';
                    globalStatusText.textContent = 'Sniffing';
                    activeInterfaceLabel.textContent = status.interface || 'Default Interface';
                } else {
                    globalLiveDot.className = 'live-dot';
                    globalStatusText.textContent = 'Offline';
                    activeInterfaceLabel.textContent = 'No active interface';
                }
            })
            .catch(() => {
                globalLiveDot.className = 'live-dot';
                globalStatusText.textContent = 'Offline';
            });
    }

    // Run status poller globally
    pollGlobalStatus();
    setInterval(pollGlobalStatus, 4000);

    /* ----------------------------------------------------
       Page Bootstrapping Routing
    ------------------------------------------------------- */
    const pageId = window.activePage;
    if (pageId === 'dashboard') {
        initLiveMonitorPage();
    } else if (pageId === 'upload') {
        initPcapUploadPage();
    } else if (pageId === 'statistics') {
        initGlobalStatsPage();
    }

    /* ----------------------------------------------------
       Feature 1 & 2: Live Monitor Codebase
    ------------------------------------------------------- */
    function initLiveMonitorPage() {
        const interfaceSelect = document.getElementById('interface-select');
        const filterSelect = document.getElementById('filter-select');
        const searchInput = document.getElementById('search-input');
        const startBtn = document.getElementById('start-btn');
        const stopBtn = document.getElementById('stop-btn');
        const clearBtn = document.getElementById('clear-btn');

        // Initial fetch network interfaces
        fetch('/api/interfaces')
            .then(res => res.json())
            .then(interfaces => {
                interfaceSelect.innerHTML = '<option value="">Select Interface...</option>';
                interfaces.forEach(iface => {
                    const opt = document.createElement('option');
                    opt.value = iface.id;
                    opt.textContent = `${iface.name} [${iface.ip}] (${iface.description})`;
                    interfaceSelect.appendChild(opt);
                });
            })
            .catch(() => {
                interfaceSelect.innerHTML = '<option value="">Failed to load interfaces</option>';
            });

        // Initialize Live Monitor telemetry charts
        initLiveCharts();

        // Control binds
        startBtn.addEventListener('click', () => {
            const selectedIface = interfaceSelect.value;
            const selectedProto = filterSelect.value;
            
            fetch('/api/capture/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    interface: selectedIface,
                    protocol: selectedProto
                })
            })
            .then(res => res.json())
            .then(data => {
                if (data.error) {
                    alert('Start Error: ' + data.error);
                } else {
                    startBtn.disabled = true;
                    interfaceSelect.disabled = true;
                    stopBtn.disabled = false;
                    startLiveMonitoring();
                }
            });
        });

        stopBtn.addEventListener('click', () => {
            fetch('/api/capture/stop', { method: 'POST' })
                .then(res => res.json())
                .then(() => {
                    startBtn.disabled = false;
                    interfaceSelect.disabled = false;
                    stopBtn.disabled = true;
                    stopLiveMonitoring();
                });
        });

        clearBtn.addEventListener('click', () => {
            fetch('/api/capture/clear', { method: 'POST' })
                .then(() => {
                    document.getElementById('packet-table-body').innerHTML = 
                        '<tr class="table-info-row"><td colspan="7">Buffer cleared. Ready to sniff.</td></tr>';
                    resetLiveCharts();
                    document.getElementById('metric-total-packets').textContent = '0';
                    document.getElementById('metric-avg-size').textContent = '0 B';
                    document.getElementById('metric-packet-rate').textContent = '0 p/s';
                    document.getElementById('metric-throughput').textContent = '0.0 Kbps';
                    hideInspector('live');
                });
        });

        // Sync control status on page load
        fetch('/api/capture/status')
            .then(res => res.json())
            .then(status => {
                if (status.running) {
                    startBtn.disabled = true;
                    interfaceSelect.disabled = true;
                    stopBtn.disabled = false;
                    
                    // Match dropdown interface
                    for(let i=0; i<interfaceSelect.options.length; i++){
                        if(interfaceSelect.options[i].value === status.interface) {
                            interfaceSelect.selectedIndex = i;
                            break;
                        }
                    }
                    startLiveMonitoring();
                }
            });

        // Auto Refresh filters on inputs
        filterSelect.addEventListener('change', () => { if(!pollIntervalId) fetchLivePackets(); });
        let searchTimeout;
        searchInput.addEventListener('input', () => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                if(!pollIntervalId) fetchLivePackets();
            }, 300);
        });
    }

    function startLiveMonitoring() {
        fetchLivePackets();
        fetchLiveStats();
        pollIntervalId = setInterval(() => {
            fetchLivePackets();
            fetchLiveStats();
        }, POLL_INTERVAL_MS);
    }

    function stopLiveMonitoring() {
        if (pollIntervalId) {
            clearInterval(pollIntervalId);
            pollIntervalId = null;
        }
    }

    function fetchLivePackets() {
        const proto = document.getElementById('filter-select').value;
        const query = encodeURIComponent(document.getElementById('search-input').value);
        
        fetch(`/api/packets?protocol=${proto}&search=${query}&limit=50`)
            .then(res => res.json())
            .then(data => {
                renderPacketTable(data.packets, 'packet-table-body', 'live');
            });
    }

    function fetchLiveStats() {
        fetch('/api/stats')
            .then(res => res.json())
            .then(stats => {
                // Update live metric indicators
                document.getElementById('metric-total-packets').textContent = stats.total_captured || 0;
                document.getElementById('metric-avg-size').textContent = (stats.avg_packet_size || 0) + ' B';
                document.getElementById('metric-packet-rate').textContent = (stats.packet_rate || 0) + ' p/s';
                document.getElementById('metric-throughput').textContent = (stats.data_rate_kbps || 0.0) + ' Kbps';

                // Update charts
                updateLiveCharts(stats);
            });
    }

    /* ----------------------------------------------------
       Feature 8: Real-Time Charts Setup
    ------------------------------------------------------- */
    function initLiveCharts() {
        const ctxProtocol = document.getElementById('live-protocol-chart');
        const ctxTimeline = document.getElementById('live-timeline-chart');

        if (!ctxProtocol || !ctxTimeline) return;

        // 1. Live Protocol Distribution Pie Chart
        liveCharts.protocol = new Chart(ctxProtocol, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'ARP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [
                        PROTOCOL_COLORS.TCP,
                        PROTOCOL_COLORS.UDP,
                        PROTOCOL_COLORS.ICMP,
                        PROTOCOL_COLORS.ARP,
                        PROTOCOL_COLORS.Other
                    ],
                    borderWidth: 1,
                    borderColor: 'rgba(255, 255, 255, 0.05)'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#94a3b8', font: { family: 'Outfit' } }
                    }
                }
            }
        });

        // 2. Live Flow Timeline Line Chart
        liveCharts.timeline = new Chart(ctxTimeline, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Bandwidth (Kbps)',
                    data: [],
                    borderColor: '#818cf8',
                    backgroundColor: 'rgba(129, 140, 248, 0.15)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        ticks: { color: '#94a3b8', font: { family: 'Outfit' } },
                        grid: { color: 'rgba(255,255,255,0.03)' }
                    },
                    y: {
                        ticks: { color: '#94a3b8', font: { family: 'Outfit' } },
                        grid: { color: 'rgba(255,255,255,0.03)' }
                    }
                }
            }
        });
    }

    function updateLiveCharts(stats) {
        if (!liveCharts.protocol || !liveCharts.timeline) return;

        // Update pie
        const percentages = stats.protocol_percentages || {};
        liveCharts.protocol.data.datasets[0].data = [
            percentages.TCP || 0,
            percentages.UDP || 0,
            percentages.ICMP || 0,
            percentages.ARP || 0,
            percentages.Other || 0
        ];
        liveCharts.protocol.update();

        // Update Line timeline (sliding window of 15 samples)
        const timestamp = new Date().toLocaleTimeString();
        const rate = stats.data_rate_kbps || 0;
        
        liveCharts.timeline.data.labels.push(timestamp);
        liveCharts.timeline.data.datasets[0].data.push(rate);

        if (liveCharts.timeline.data.labels.length > 15) {
            liveCharts.timeline.data.labels.shift();
            liveCharts.timeline.data.datasets[0].data.shift();
        }
        liveCharts.timeline.update();
    }

    function resetLiveCharts() {
        if (liveCharts.protocol) {
            liveCharts.protocol.data.datasets[0].data = [0, 0, 0, 0, 0];
            liveCharts.protocol.update();
        }
        if (liveCharts.timeline) {
            liveCharts.timeline.data.labels = [];
            liveCharts.timeline.data.datasets[0].data = [];
            liveCharts.timeline.update();
        }
    }

    /* ----------------------------------------------------
       Feature 7: Wireshark Table & Inspector
    ------------------------------------------------------- */
    function renderPacketTable(packets, tableBodyId, type) {
        const tableBody = document.getElementById(tableBodyId);
        if (!tableBody) return;

        if (packets.length === 0) {
            tableBody.innerHTML = `<tr class="table-info-row"><td colspan="7">No matching packets captured.</td></tr>`;
            return;
        }

        // Keep track of current selected packet index/timestamp to keep highlighted row active
        const selectedId = selectedPacketData ? selectedPacketData.timestamp : null;

        tableBody.innerHTML = '';
        packets.forEach((pkt, idx) => {
            const tr = document.createElement('tr');
            
            // Apply protocol-specific style classes
            const proto = pkt.protocol.toUpperCase();
            if (proto === 'TCP') tr.className = 'row-tcp';
            else if (proto === 'UDP') tr.className = 'row-udp';
            else if (proto === 'ICMP') tr.className = 'row-icmp';
            else if (proto === 'ARP') tr.className = 'row-arp';
            else tr.className = 'row-other';

            if (pkt.timestamp === selectedId) {
                tr.classList.add('selected');
            }

            // Shorten timestamp for table
            const timeStr = pkt.timestamp.includes('T') ? pkt.timestamp.split('T')[1].substring(0,8) : pkt.timestamp;

            tr.innerHTML = `
                <td>${pkt.id || (idx + 1)}</td>
                <td>${timeStr}</td>
                <td>${pkt.src_ip}</td>
                <td>${pkt.dst_ip}</td>
                <td><span class="badge-protocol badge-${proto.toLowerCase()}">${proto}</span></td>
                <td>${pkt.length}</td>
                <td title="${pkt.info}">${pkt.info}</td>
            `;

            // Row click event to load details inside Inspector
            tr.addEventListener('click', () => {
                // Clear selected style on siblings
                Array.from(tableBody.querySelectorAll('tr')).forEach(r => r.classList.remove('selected'));
                tr.classList.add('selected');
                
                selectedPacketData = pkt;
                loadPacketDetailsInspector(pkt, type);
            });

            tableBody.appendChild(tr);
        });
    }

    function loadPacketDetailsInspector(pkt, type) {
        const prefix = type === 'pcap' ? 'pcap-' : '';
        const instruction = document.getElementById(`${prefix}inspector-instruction`);
        const detailsView = document.getElementById(`${prefix}inspector-details-view`);
        const tabsContainer = document.getElementById(`${prefix}inspector-tabs-container`);
        const fieldsDisplay = document.getElementById(`${prefix}header-fields-display`);
        const payloadSection = document.getElementById(`${prefix}payload-dump-section`);
        const hexBox = document.getElementById(`${prefix}payload-hex-box`);
        const asciiBox = document.getElementById(`${prefix}payload-ascii-box`);

        if (!detailsView) return;

        // Hide helper instructions
        instruction.style.display = 'none';
        detailsView.style.display = 'flex';

        // Clear contents
        tabsContainer.innerHTML = '';
        fieldsDisplay.innerHTML = '';
        payloadSection.style.display = 'none';

        const layers = pkt.layers || {};
        const layerNames = Object.keys(layers);

        if (layerNames.length === 0) {
            fieldsDisplay.innerHTML = `<div class="field-row"><span class="field-key">No headers parsed</span><span class="field-val">Raw frame</span></div>`;
            return;
        }

        // Add Layer Tabs
        layerNames.forEach((layerName, i) => {
            const btn = document.createElement('button');
            btn.className = `tab-btn ${i === 0 ? 'active' : ''}`;
            btn.textContent = layerName;
            btn.addEventListener('click', () => {
                Array.from(tabsContainer.querySelectorAll('.tab-btn')).forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                renderLayerFields(layers[layerName], fieldsDisplay);
            });
            tabsContainer.appendChild(btn);
        });

        // Initialize display with the first layer
        renderLayerFields(layers[layerNames[0]], fieldsDisplay);

        // Populate hex payloads if available
        if (pkt.payload) {
            payloadSection.style.display = 'block';
            hexBox.textContent = pkt.payload.hex;
            asciiBox.textContent = pkt.payload.ascii;
        }
    }

    function renderLayerFields(layerFields, container) {
        container.innerHTML = '';
        Object.entries(layerFields).forEach(([key, val]) => {
            const row = document.createElement('div');
            row.className = 'field-row highlight';
            row.innerHTML = `
                <span class="field-key">${key.toUpperCase()}</span>
                <span class="field-val">${val !== null ? val : 'None'}</span>
            `;
            container.appendChild(row);
        });
    }

    function hideInspector(type) {
        const prefix = type === 'pcap' ? 'pcap-' : '';
        const instruction = document.getElementById(`${prefix}inspector-instruction`);
        const detailsView = document.getElementById(`${prefix}inspector-details-view`);
        if (instruction && detailsView) {
            instruction.style.display = 'inline-block';
            detailsView.style.display = 'none';
        }
        selectedPacketData = null;
    }

    /* ----------------------------------------------------
       Feature 6: PCAP File Analyzer
    ------------------------------------------------------- */
    function initPcapUploadPage() {
        const dropzone = document.getElementById('dropzone');
        const fileInput = document.getElementById('pcap-file-input');
        const progressWrapper = document.getElementById('upload-progress-wrapper');
        const barFill = document.getElementById('upload-bar-fill');
        const percentLabel = document.getElementById('upload-percent');
        const processingText = document.getElementById('processing-text');
        const errorAlert = document.getElementById('upload-error-alert');
        const dashboard = document.getElementById('pcap-analytics-dashboard');

        if (!dropzone) return;

        // Prevent browser defaults
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, e => {
                e.preventDefault();
                e.stopPropagation();
            }, false);
        });

        // Toggle hover styles
        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, () => dropzone.classList.add('dragover'), false);
        });
        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, () => dropzone.classList.remove('dragover'), false);
        });

        // Handle drop
        dropzone.addEventListener('drop', e => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                handlePcapUpload(files[0]);
            }
        });

        // Handle file browse
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                handlePcapUpload(fileInput.files[0]);
            }
        });

        function handlePcapUpload(file) {
            // Validate client side size limit (16MB)
            const MAX_SIZE = 16 * 1024 * 1024;
            if (file.size > MAX_SIZE) {
                showUploadError('Invalid File Size', 'The uploaded capture exceeds the 16MB file limit size.');
                return;
            }

            // Validate extension
            const ext = file.name.split('.').pop().toLowerCase();
            if (ext !== 'pcap' && ext !== 'pcapng') {
                showUploadError('Invalid Extension', 'Only standard .pcap and .pcapng files are supported.');
                return;
            }

            // Hide previous stats and errors
            errorAlert.style.display = 'none';
            dashboard.style.display = 'none';
            
            // Show upload progress wrapper
            progressWrapper.style.display = 'flex';
            document.getElementById('uploading-filename').textContent = file.name;
            barFill.style.style = '0%';
            percentLabel.textContent = '0%';
            processingText.style.display = 'none';

            // AJAX Upload using XMLHttpRequest for upload progress
            const xhr = new XMLHttpRequest();
            const formData = new FormData();
            formData.append('file', file);

            xhr.upload.addEventListener('progress', e => {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    barFill.style.width = percent + '%';
                    percentLabel.textContent = percent + '%';
                    
                    if (percent === 100) {
                        processingText.style.display = 'block';
                    }
                }
            });

            xhr.onreadystatechange = () => {
                if (xhr.readyState === XMLHttpRequest.DONE) {
                    progressWrapper.style.display = 'none';
                    if (xhr.status === 200) {
                        try {
                            const response = JSON.parse(xhr.responseText);
                            renderPcapAnalysis(response);
                        } catch (err) {
                            showUploadError('Parsing Failed', 'The system encountered an error decapsulating the PCAP headers.');
                        }
                    } else {
                        let errMsg = 'Capture processing failed.';
                        try {
                            const errResp = JSON.parse(xhr.responseText);
                            errMsg = errResp.error || errMsg;
                        } catch(e){}
                        showUploadError('Server Error', errMsg);
                    }
                }
            };

            xhr.open('POST', '/api/upload', true);
            xhr.send(formData);
        }

        function showUploadError(title, message) {
            errorAlert.style.display = 'flex';
            document.getElementById('error-title').textContent = title;
            document.getElementById('error-message').textContent = message;
            progressWrapper.style.display = 'none';
        }

        function renderPcapAnalysis(data) {
            dashboard.style.display = 'block';
            hideInspector('pcap');

            // 1. Render Metadata Summary
            document.getElementById('meta-filename').textContent = data.filename;
            document.getElementById('meta-size').textContent = (data.file_size / (1024 * 1024)).toFixed(2) + ' MB';
            document.getElementById('meta-packets').textContent = data.stats.total_packets;
            document.getElementById('meta-avg-size').textContent = data.stats.avg_packet_size + ' B';
            document.getElementById('meta-rate').textContent = (data.stats.data_rate_kbps || 0.0) + ' Kbps';

            // 2. NumPy length statistics
            const advanced = data.advanced || {};
            const lenStats = advanced.length_stats || {};
            document.getElementById('pcap-min-len').textContent = (lenStats.min || 0) + ' B';
            document.getElementById('pcap-max-len').textContent = (lenStats.max || 0) + ' B';
            document.getElementById('pcap-median-len').textContent = (lenStats.median || 0) + ' B';
            document.getElementById('pcap-std-len').textContent = (lenStats.std || 0.0).toFixed(2);

            // 3. Render PCAP Charts
            renderPcapCharts(data.stats, advanced);

            // 4. Render Table list
            renderPacketTable(data.packets, 'pcap-table-body', 'pcap');
        }

        let pcapChartsList = {};
        function renderPcapCharts(stats, advanced) {
            // Destroy existing charts to prevent canvas overlays
            Object.values(pcapChartsList).forEach(c => c.destroy());
            pcapChartsList = {};

            const ctxProtocol = document.getElementById('pcap-protocol-chart');
            const ctxTimeline = document.getElementById('pcap-timeline-chart');
            const ctxSources = document.getElementById('pcap-sources-chart');
            const ctxPorts = document.getElementById('pcap-ports-chart');

            // Doughnut Chart (Protocols)
            pcapChartsList.protocol = new Chart(ctxProtocol, {
                type: 'doughnut',
                data: {
                    labels: ['TCP', 'UDP', 'ICMP', 'ARP', 'Other'],
                    datasets: [{
                        data: [
                            stats.protocol_counts.TCP || 0,
                            stats.protocol_counts.UDP || 0,
                            stats.protocol_counts.ICMP || 0,
                            stats.protocol_counts.ARP || 0,
                            stats.protocol_counts.Other || 0
                        ],
                        backgroundColor: [PROTOCOL_COLORS.TCP, PROTOCOL_COLORS.UDP, PROTOCOL_COLORS.ICMP, PROTOCOL_COLORS.ARP, PROTOCOL_COLORS.Other],
                        borderWidth: 1,
                        borderColor: 'rgba(255, 255, 255, 0.05)'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'right', labels: { color: '#94a3b8', font: { family: 'Outfit' } } }
                    }
                }
            });

            // Timeline Chart (NumPy timeline series)
            const timelineData = advanced.timeline_series || [];
            pcapChartsList.timeline = new Chart(ctxTimeline, {
                type: 'line',
                data: {
                    labels: timelineData.map(t => t.time),
                    datasets: [{
                        label: 'Throughput (Bytes)',
                        data: timelineData.map(t => t.bytes),
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.15)',
                        fill: true,
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { color: 'rgba(255,255,255,0.03)' } },
                        y: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { color: 'rgba(255,255,255,0.03)' } }
                    }
                }
            });

            // Top Source IP Addresses
            const sources = stats.top_sources || [];
            pcapChartsList.sources = new Chart(ctxSources, {
                type: 'bar',
                data: {
                    labels: sources.map(s => s.ip),
                    datasets: [{
                        label: 'Packets Sent',
                        data: sources.map(s => s.count),
                        backgroundColor: '#6366f1',
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { display: false } },
                        y: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { color: 'rgba(255,255,255,0.03)' } }
                    }
                }
            });

            // Top Destination Ports
            const ports = stats.top_ports || [];
            pcapChartsList.ports = new Chart(ctxPorts, {
                type: 'bar',
                data: {
                    labels: ports.map(p => 'Port ' + p.port),
                    datasets: [{
                        label: 'Frequency',
                        data: ports.map(p => p.count),
                        backgroundColor: '#fbbf24',
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { display: false } },
                        y: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { color: 'rgba(255,255,255,0.03)' } }
                    }
                }
            });
        }
    }

    /* ----------------------------------------------------
       Feature 4: Global Stats View
    ------------------------------------------------------- */
    let globalStatsCharts = {};
    function initGlobalStatsPage() {
        initGlobalStatsCharts();
        fetchGlobalStats();
        // Refresh every 3 seconds to update charts on live network metrics
        setInterval(fetchGlobalStats, 3000);
    }

    function initGlobalStatsCharts() {
        const ctxProtocol = document.getElementById('stats-protocol-chart');
        const ctxTimeline = document.getElementById('stats-timeline-chart');
        const ctxSources = document.getElementById('stats-sources-chart');
        const ctxPorts = document.getElementById('stats-ports-chart');

        if (!ctxProtocol) return;

        globalStatsCharts.protocol = new Chart(ctxProtocol, {
            type: 'pie',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'ARP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: [PROTOCOL_COLORS.TCP, PROTOCOL_COLORS.UDP, PROTOCOL_COLORS.ICMP, PROTOCOL_COLORS.ARP, PROTOCOL_COLORS.Other],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'right', labels: { color: '#94a3b8', font: { family: 'Outfit' } } } }
            }
        });

        globalStatsCharts.timeline = new Chart(ctxTimeline, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Bandwidth (Bytes)',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { color: 'rgba(255,255,255,0.03)' } },
                    y: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { color: 'rgba(255,255,255,0.03)' } }
                }
            }
        });

        globalStatsCharts.sources = new Chart(ctxSources, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Packets Transmitted',
                    data: [],
                    backgroundColor: '#6366f1',
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { display: false } },
                    y: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { color: 'rgba(255,255,255,0.03)' } }
                }
            }
        });

        globalStatsCharts.ports = new Chart(ctxPorts, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Frames Frequency',
                    data: [],
                    backgroundColor: '#fbbf24',
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { display: false } },
                    y: { ticks: { color: '#94a3b8', font: { family: 'Outfit' } }, grid: { color: 'rgba(255,255,255,0.03)' } }
                }
            }
        });
    }

    function fetchGlobalStats() {
        fetch('/api/stats')
            .then(res => res.json())
            .then(stats => {
                // Update text metric widgets
                document.getElementById('stats-total-bytes').textContent = formatBytes(stats.data_volume_bytes || 0);
                document.getElementById('stats-avg-size').textContent = (stats.avg_packet_size || 0) + ' B';
                document.getElementById('stats-packet-rate').textContent = (stats.packet_rate || 0) + ' p/s';
                document.getElementById('stats-throughput').textContent = (stats.data_rate_kbps || 0.0) + ' Kbps';

                if (!globalStatsCharts.protocol) return;

                // Update Doughnut Protocol Chart
                const percentages = stats.protocol_percentages || {};
                globalStatsCharts.protocol.data.datasets[0].data = [
                    percentages.TCP || 0,
                    percentages.UDP || 0,
                    percentages.ICMP || 0,
                    percentages.ARP || 0,
                    percentages.Other || 0
                ];
                globalStatsCharts.protocol.update();

                // Update Timeline chart (adds continuous measurements)
                const currentLabel = new Date().toLocaleTimeString();
                globalStatsCharts.timeline.data.labels.push(currentLabel);
                globalStatsCharts.timeline.data.datasets[0].data.push(stats.data_volume_bytes || 0);
                if (globalStatsCharts.timeline.data.labels.length > 20) {
                    globalStatsCharts.timeline.data.labels.shift();
                    globalStatsCharts.timeline.data.datasets[0].data.shift();
                }
                globalStatsCharts.timeline.update();

                // Update top talker IPs
                const sources = stats.top_sources || [];
                globalStatsCharts.sources.data.labels = sources.map(s => s.ip);
                globalStatsCharts.sources.data.datasets[0].data = sources.map(s => s.count);
                globalStatsCharts.sources.update();

                // Update top talker Ports
                const ports = stats.top_ports || [];
                globalStatsCharts.ports.data.labels = ports.map(p => 'Port ' + p.port);
                globalStatsCharts.ports.data.datasets[0].data = ports.map(p => p.count);
                globalStatsCharts.ports.update();

                // Render flow table
                renderGlobalConversationsTable(sources, stats.data_volume_bytes || 1);
            });
    }

    function renderGlobalConversationsTable(sources, totalBytes) {
        const body = document.getElementById('stats-conversations-body');
        if (!body) return;

        if (sources.length === 0) {
            body.innerHTML = `<tr class="table-info-row"><td colspan="6">No network conversations mapped. Active live monitor!</td></tr>`;
            return;
        }

        body.innerHTML = '';
        sources.forEach((item) => {
            const tr = document.createElement('tr');
            
            // Mock destination and byte breakdown for visualization (representing endpoint conversations)
            const mockDest = '192.168.1.1';
            const mockBytes = Math.round(item.count * 1500); // 1500B standard packet size approximation
            const share = ((mockBytes / totalBytes) * 100).toFixed(1);

            tr.innerHTML = `
                <td><strong>${item.ip}</strong></td>
                <td><i class="fa-solid fa-arrows-left-right text-muted"></i></td>
                <td>${mockDest}</td>
                <td>${item.count} Packets</td>
                <td>${formatBytes(mockBytes)}</td>
                <td>
                    <div style="display:flex; align-items:center; gap:8px;">
                        <span style="font-size:0.8rem; width:35px;">${share}%</span>
                        <div style="background:rgba(255,255,255,0.05); width:100px; height:6px; border-radius:3px; overflow:hidden;">
                            <div style="background:var(--primary); height:100%; width:${share}%;"></div>
                        </div>
                    </div>
                </td>
            `;
            body.appendChild(tr);
        });
    }

    // Helper functions
    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
});
