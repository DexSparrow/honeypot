const axios = require('axios');
const express = require('express');
const router = express.Router();
const { detectMaliciousPatterns } = require('../utils/detector');
const Log = require('../models/log');

function normalizeIp(ip) {
  if (!ip) return ip;
  if (ip.startsWith('::ffff:')) {
    return ip.replace('::ffff:', '');
  }
  return ip;
}

function isPrivateIP(ip) {
  return (
    ip === '::1' ||
    ip === '127.0.0.1' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    (ip.startsWith('172.') && (() => {
      const secondOctet = parseInt(ip.split('.')[1], 10);
      return secondOctet >= 16 && secondOctet <= 31;
    })())
  );
}

router.post('/analyze', async (req, res) => {
  const { payload } = req.body;

  let ip = req.headers['x-forwarded-for'] || req.ip || '';
  if (ip.includes(',')) {
    ip = ip.split(',')[0].trim();
  }
  ip = normalizeIp(ip);

  const result = detectMaliciousPatterns(payload);

  let geo = null;
  if (!isPrivateIP(ip)) {
    try {
      const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,lat,lon`);
      if (response.data.status === 'success') {
        geo = {
          country_short: response.data.countryCode,
          country_long: response.data.country,
          region: response.data.regionName,
          city: response.data.city,
          latitude: response.data.lat,
          longitude: response.data.lon,
        };
      }
    } catch (error) {
      console.error('Erreur récupération géoloc IP :', error.message);
    }
  }

  if (result.isMalicious) {
    const highestSeverity = result.patterns.length > 0
      ? result.patterns.reduce((max, p) => {
          const levels = { low: 1, medium: 2, high: 3 };
          const currentSeverity = p.severity ? p.severity.toLowerCase() : 'low';
          const maxSeverity = max.toLowerCase();
          return levels[currentSeverity] > levels[maxSeverity] ? currentSeverity : maxSeverity;
        }, 'low')
      : 'low';

    const log = new Log({
      ip,
      method: req.method,
      url: req.originalUrl,
      payload,
      detectedPatterns: result.patterns,
      highestSeverity,
      userAgent: req.headers['user-agent'],
      endpoint: '/api/analyze',
      geo,
    });

    await log.save();
  }

  // Réponse générique, on ne révèle rien au client
  res.json({ success: true, message: "Requête reçue et traitée." });
});


module.exports = router;
