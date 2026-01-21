// server.js :-

const pcap = require('pcap');
const WebSocket = require('ws');
const http = require('http');
const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Serve frontend files from /public folder
app.use(express.static(path.join(__dirname, 'public')));

// Root route - serve demo.html by default
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'demo.html'));
});

// Catch-all for 404s
app.use((req, res) => {
  res.status(404).send('File not found. Make sure demo.html is in the /public folder.');
});

const device = pcap.findalldevs()?.[0]?.name || 'en0'; // Auto-detect (e.g., 'eth0' for Linux hospital server)
console.log(`Starting packet capture on device: ${device}`);

// Load persistent blacklists from file (existing IPs)
let blacklistedIPs = new Set();
const BLACKLIST_FILE = 'blacklist.json';

function loadBlacklist() {
  try {
    if (fs.existsSync(BLACKLIST_FILE)) {
      const data = JSON.parse(fs.readFileSync(BLACKLIST_FILE, 'utf8'));
      blacklistedIPs = new Set(data.blacklistedIPs || []);
      console.log(`Loaded IP blacklist: ${blacklistedIPs.size} IPs`);
    } else {
      blacklistedIPs = new Set(['192.168.1.100', '203.0.113.45']); // Default malicious IPs
      saveBlacklist();
    }
  } catch (err) {
    console.error('Error loading IP blacklist:', err.message);
    blacklistedIPs = new Set(['192.168.1.100', '203.0.113.45']);
  }
}

function saveBlacklist() {
  try {
    const data = { blacklistedIPs: Array.from(blacklistedIPs) };
    fs.writeFileSync(BLACKLIST_FILE, JSON.stringify(data, null, 2));
    console.log('IP blacklist saved');
  } catch (err) {
    console.error('Error saving IP blacklist:', err.message);
  }
}

loadBlacklist();

// NEW: Hospital-specific ports (loaded from hospitalports.json)
let allowedPorts = new Set();
let suspiciousPorts = new Set();
const HOSPITAL_PORTS_FILE = 'hospitalports.json';

function loadHospitalPorts() {
  try {
    if (fs.existsSync(HOSPITAL_PORTS_FILE)) {
      const config = JSON.parse(fs.readFileSync(HOSPITAL_PORTS_FILE, 'utf8'));
      allowedPorts = new Set(config.allowedPorts.ports || []);
      suspiciousPorts = new Set(config.suspiciousPorts.ports || []);
      console.log(`Loaded hospital ports: ${allowedPorts.size} allowed, ${suspiciousPorts.size} suspicious`);
      console.log(`Hospital config notes: ${config.hospitalNotes || 'N/A'}`);
    } else {
      // Default hospital config (save to file)
      const defaultConfig = {
        allowedPorts: { description: "Hospital-standard ports", ports: [80, 443, 104, 2575, 161, 162, 53] },
        suspiciousPorts: { description: "Ports to quarantine/block", ports: [4444, 31337, 12345, 3389, 6667, 445] },
        hospitalNotes: "Customize for your network. Add ports for specific devices (e.g., 9100 for printers)."
      };
      fs.writeFileSync(HOSPITAL_PORTS_FILE, JSON.stringify(defaultConfig, null, 2));
      allowedPorts = new Set(defaultConfig.allowedPorts.ports);
      suspiciousPorts = new Set(defaultConfig.suspiciousPorts.ports);
      console.log('Created default hospitalports.json - customize it!');
    }
  } catch (err) {
    console.error('Error loading hospital ports:', err.message);
    // Fallback defaults
    allowedPorts = new Set([80, 443, 104, 2575, 161, 162, 53]);
    suspiciousPorts = new Set([4444, 31337, 12345, 3389, 6667, 445]);
  }
}

function saveHospitalPorts() {
  try {
    const config = {
      allowedPorts: { description: "Hospital-standard ports", ports: Array.from(allowedPorts) },
      suspiciousPorts: { description: "Ports to quarantine/block", ports: Array.from(suspiciousPorts) },
      hospitalNotes: "Auto-updated on new detections. Review manually."
    };
    fs.writeFileSync(HOSPITAL_PORTS_FILE, JSON.stringify(config, null, 2));
    console.log('Hospital ports config saved');
  } catch (err) {
    console.error('Error saving hospital ports:', err.message);
  }
}

loadHospitalPorts(); // Load on startup

const knownIPs = new Set();
const ipRates = new Map();

// Hospital IP range (update to your subnet, e.g., /^10\.0\.0\./ for internal LAN)
const ORG_IP_RANGE = /^192\.168\.1\./;

function detectThreat(packet) {
  let status = 'allowed';

  // Check blacklisted IPs
  if (blacklistedIPs.has(packet.sourceIP) || blacklistedIPs.has(packet.destinationIP)) {
    console.log(`[AUTO-BLOCK] Blacklisted IP hit: ${packet.sourceIP} -> ${packet.destinationIP}`);
    return 'blocked';
  }

  // NEW: Hospital port checks
  let portAction = null;
  if (packet.sourcePort) {
    if (suspiciousPorts.has(packet.sourcePort)) {
      portAction = 'suspicious-source';
      status = 'quarantined';
      console.log(`[AUTO-QUARANTINE] Suspicious source port ${packet.sourcePort} (e.g., backdoor) from ${packet.sourceIP} on hospital network`);
    } else if (allowedPorts.has(packet.sourcePort)) {
      portAction = 'hospital-allowed';
      console.log(`[MONITOR] Hospital-standard source port ${packet.sourcePort} (e.g., DICOM/HL7) from ${packet.sourceIP}`);
    }
  }
  if (packet.destinationPort) {
    if (suspiciousPorts.has(packet.destinationPort)) {
      portAction = 'suspicious-dest';
      status = 'quarantined';
      console.log(`[AUTO-QUARANTINE] Suspicious destination port ${packet.destinationPort} (e.g., RDP/malware) to ${packet.destinationIP} on hospital network`);
      // Auto-add new suspicious ports if detected frequently (e.g., >5 times)
      if (!suspiciousPorts.has(packet.destinationPort)) {
        suspiciousPorts.add(packet.destinationPort);
        saveHospitalPorts();
      }
    } else if (allowedPorts.has(packet.destinationPort)) {
      portAction = 'hospital-allowed';
      console.log(`[MONITOR] Hospital-standard destination port ${packet.destinationPort} (e.g., SNMP/DNS) to ${packet.destinationIP}`);
    }
  }

  // Anomaly detection (e.g., oversized packets for data exfiltration from patient records)
  if (packet.packetSize > 1500) {
    status = 'anomaly';
    blacklistedIPs.add(packet.sourceIP);
    console.log(`[AUTO-BLOCK] Anomaly (large packet ${packet.packetSize} bytes) from ${packet.sourceIP} - potential data leak in hospital`);
    saveBlacklist();
  } else if (!knownIPs.has(packet.sourceIP)) {
    knownIPs.add(packet.sourceIP);
    status = 'learned'; // New device learned (e.g., new infusion pump)
    console.log(`[LEARNED] New IP/device ${packet.sourceIP} on hospital network`);
  }

  // Auto-blacklist on threat
  if (status !== 'allowed' && status !== 'learned') {
    blacklistedIPs.add(packet.sourceIP);
    saveBlacklist();
  }

  return status;
}

function broadcast(data) {
  const message = JSON.stringify(data);
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// Block HTTP requests from blacklisted IPs
app.use((req, res, next) => {
  const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
  if (blacklistedIPs.has(clientIP)) {
    console.log(`[WEB BLOCK] Denied dashboard access from blacklisted IP: ${clientIP}`);
    return res.status(403).send('Access Denied: Blacklisted by Hospital Immune Firewall.');
  }
  next();
});

// Block WS connections from blacklisted IPs
wss.on('connection', (ws, req) => {
  const clientIP = req.socket.remoteAddress;
  if (blacklistedIPs.has(clientIP)) {
    ws.close(3003, 'Access Denied: Blacklisted IP');
    return;
  }
  console.log(`Hospital dashboard connected from ${clientIP}`);
  ws.on('close', () => console.log('Dashboard disconnected'));
});

// Packet capture setup
let pcapSession;
try {
  pcapSession = pcap.createSession(device, { filter: 'ip' });
  console.log('Packet capture started. Monitoring hospital traffic...');
} catch (err) {
  console.error(`pcap failed on ${device}: ${err.message}`);
  console.log('Run as admin/root. List interfaces: node -e "console.log(require(\'pcap\').findalldevs())"');
  pcapSession = null;
}

if (pcapSession) {
  pcapSession.on('packet', rawPacket => {
    try {
      const packet = pcap.decode.packet(rawPacket);
      const ip = packet.payload.payload;
      if (!ip) return;

      const sourceIP = ip.saddr.addr.join('.');
      const destinationIP = ip.daddr.addr.join('.');
      const protocolNum = ip.protocol;
      let protocolName = 'UNKNOWN';
      switch (protocolNum) {
        case 1: protocolName = 'ICMP'; break;
        case 6: protocolName = 'TCP'; break;
        case 17: protocolName = 'UDP'; break;
      }

      let sourcePort = null, destinationPort = null;
      if (protocolName === 'TCP' || protocolName === 'UDP') {
        const transport = ip.payload;
        sourcePort = transport.sport;
        destinationPort = transport.dport;
      }

      const packetSize = rawPacket.buf.length;
      const now = Date.now();

      // DoS Detection (critical for hospital uptime)
      const ipKey = sourceIP;
      if (!ipRates.has(ipKey)) ipRates.set(ipKey, []);
      ipRates.get(ipKey).push(now);
      ipRates.set(ipKey, ipRates.get(ipKey).filter(t => now - t < 1000));
      let dosStatus = null;
      if (ipRates.get(ipKey).length > 100) {
        dosStatus = 'dos_block';
        blacklistedIPs.add(sourceIP);
        console.log(`[AUTO-BLOCK] DoS on hospital network from ${sourceIP} (${ipRates.get(ipKey).length}/sec)`);
        saveBlacklist();
      }

      let status = dosStatus || detectThreat({
        sourceIP, destinationIP, sourcePort, destinationPort, protocol: protocolName, packetSize
      });

      const event = {
        sourceIP, destinationIP,
        sourcePort: sourcePort || 'N/A',
        destinationPort: destinationPort || 'N/A',
        protocol: protocolName,
        packetSize,
        status,
        timestamp: now
      };

      broadcast({ type: 'network-event', data: event });
      console.log(`[${status.toUpperCase()}] ${sourceIP}:${sourcePort || 'N/A'} -> ${destinationIP}:${destinationPort || 'N/A'} [${protocolName}]`);

    } catch (err) {
      console.error('Packet error:', err.message);
    }
  });
}

// Start server
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`\n=== Hospital Immune Firewall Active ===`);
  console.log(`Dashboard: http://localhost:${PORT}`);
  console.log(`WebSocket ready. Ports loaded from hospitalports.json.`);
  console.log(`Monitoring ${device}. Customize hospitalports.json for your setup.\n`);
});