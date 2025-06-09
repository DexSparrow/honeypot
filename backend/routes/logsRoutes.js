const express = require('express');
const router = express.Router();
const Log = require('../models/log');
const PortScanLog = require('../models/portScanLog');  // nouveau modèle

// GET /api/logs - liste des logs généraux
router.get('/general', async (req, res) => {
  try {
    const logs = await Log.find().sort({ date: -1 }).limit(100);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/logs/portscan - liste des logs de scan de ports
router.get('/portscan', async (req, res) => {
  try {
    const portscanLogs = await PortScanLog.find().sort({ date: -1 }).limit(100);
    res.json(portscanLogs);
  } catch (err) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/logs/stats - statistiques sur les scans de ports
router.get('/stats/portscan', async (req, res) => {
  try {
    const scansParPort = await PortScanLog.aggregate([
      { $group: { _id: "$port", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    const topIPs = await PortScanLog.aggregate([
      { $group: { _id: "$ip", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    const totalLogs = await PortScanLog.countDocuments();

    const lastLog = await PortScanLog.findOne().sort({ date: -1 });

    res.json({
      totalLogs,
      lastActivity: lastLog?.date || null,
      scansParPort,
      topIPs
    });
  } catch (err) {
    console.error("Erreur /stats/portscan:", err);
    res.status(500).json({ error: 'Erreur lors du calcul des statistiques' });
  }
});


// GET /api/logs/stats/general - statistiques sur les logs généraux
router.get('/stats/general', async (req, res) => {
  try {
    const totalLogs = await Log.countDocuments();

    const methods = await Log.aggregate([
      { $group: { _id: "$method", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    const topURLs = await Log.aggregate([
      { $group: { _id: "$url", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ]);

    const lastLog = await Log.findOne().sort({ date: -1 });

    res.json({
      totalLogs,
      lastActivity: lastLog?.date || null,
      methods,
      topURLs
    });
  } catch (err) {
    console.error("Erreur /stats/general:", err);
    res.status(500).json({ error: 'Erreur lors du calcul des statistiques générales' });
  }
});



module.exports = router;
