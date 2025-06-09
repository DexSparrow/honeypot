const pcap = require('pcap');
const net = require('net');
const PortScanLog = require('../models/portScanLog');

const honeypotPorts = [21, 22, 23, 3306, 5432, 6379];
const networkInterface = 'any'; // Adapter selon ta config
const synScanFilter = 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0';

const recentLogsMap = new Map();
const openedPorts = new Set();
const activeServers = [];

function formatIp(addr) {
  if (!addr || !Array.isArray(addr)) return 'inconnu';
  if (addr.length === 4) {
    return addr.join('.');
  } else if (addr.length === 16) {
    const hexPairs = [];
    for (let i = 0; i < 16; i += 2) {
      hexPairs.push(((addr[i] << 8) | addr[i + 1]).toString(16));
    }
    return hexPairs.join(':');
  }
  return 'inconnu';
}

function logEvent(ip, port, type) {
  const key = `${ip}:${port}:${type}`;
  const now = Date.now();
  const lastLogTime = recentLogsMap.get(key);

  if (lastLogTime && (now - lastLogTime) < 10000) {
    return;
  }

  recentLogsMap.set(key, now);
  console.log(`[HONEYPOT${type === 'SYN_SCAN' ? '-SYN' : ''}] ${type === 'SYN_SCAN' ? 'Scan SYN détecté' : 'Connexion détectée'} depuis ${ip} vers port ${port}`);

  PortScanLog.create({ ip, port, type }).catch(err => {
    console.error('[!] Erreur MongoDB:', err.message);
  });

  setTimeout(() => {
    recentLogsMap.delete(key);
  }, 60000);
}

function startSynScanHoneypot() {
  const pcapSession = pcap.createSession(networkInterface, synScanFilter);
  console.log(`[HONEYPOT-SYN] Surveillance SYN sur interface ${networkInterface}`);

  pcapSession.on('packet', (rawPacket) => {
    try {
      const packet = pcap.decode.packet(rawPacket);
      const ip = packet.payload.payload;
      const tcp = ip.payload;

      const srcIp = formatIp(ip?.saddr?.addr);
      const dstPort = tcp?.dport;

      if (honeypotPorts.includes(dstPort)) {
        logEvent(srcIp, dstPort, 'SYN_SCAN');
      }
    } catch (err) {
      console.error('[!] Erreur traitement paquet:', err.message);
    }
  });
}

function startPortHoneypot() {
  honeypotPorts.forEach((port) => {
    if (openedPorts.has(port)) {
      console.log(`[HONEYPOT] Port ${port} déjà ouvert. Saut...`);
      return;
    }

    const server = net.createServer((socket) => {
      let ip = socket.remoteAddress || 'unknown';
      if (ip.startsWith('::ffff:')) ip = ip.substring(7);

      logEvent(ip, port, 'CONNECTION_ATTEMPT');

      socket.destroy();
    });

    server.listen(port, '0.0.0.0', () => {
      console.log(`[HONEYPOT] Port ${port} ouvert sur 0.0.0.0`);
      openedPorts.add(port);
      activeServers.push(server);
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.warn(`[!] Port ${port} déjà utilisé. Ignoré.`);
      } else {
        console.error(`[!] Erreur port ${port}:`, err.message);
      }
    });
  });
}

function stopHoneypotPortScan() {
  console.log('[HONEYPOT] Arrêt des serveurs de ports...');
  activeServers.forEach((server) => {
    server.close(() => {
      console.log('[HONEYPOT] Serveur fermé');
    });
  });
  openedPorts.clear();
  activeServers.length = 0;
}

function startHoneypotPortScan() {
  startSynScanHoneypot();
  startPortHoneypot();
}

// Exporter la fonction d’arrêt pour qu’elle soit appelée lors de la fermeture du serveur principal

module.exports = { startHoneypotPortScan };
