const express = require('express');
const router = express.Router();
const Log = require('../models/log'); 
const axios = require('axios');


const honeypotPaths = [
  "/admin", "/login", "/wp-login.php", "/phpmyadmin", "/server-status",
  "/config", "/backup", "/admin1", "/admin-old", "/administrator",
  "/user/login", "/admin.php", "/cpanel", "/adminpanel", "/dashboard",
  "/root", "/manager", "/login.php", "/wp-admin", "/admin/login",
  "/controlpanel", "/admin123", "/system", "/backend", "/adminarea",
  "/admin-console", "/adminarea/login", "/auth", "/admin/dashboard",
  "/admin-console/login", "/secret", "/hidden", "/private", "/test",
  "/test.php", "/shell", "/console", "/admin1.php", "/admin2", "/admin2.php"
];

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

const getClientIp = (req) => {
  const xForwardedFor = req.headers['x-forwarded-for'];
  if (xForwardedFor) {
    return normalizeIp(xForwardedFor.split(',')[0].trim());
  }
  return normalizeIp(req.connection?.remoteAddress || req.socket?.remoteAddress || req.ip);
};

honeypotPaths.forEach(path => {
  router.all(path, async (req, res) => {
    const clientIp = getClientIp(req);

    let geo = null;

    if (isPrivateIP(clientIp)) {
      console.log(`[HONEYPOT] Access to fake route ${path} by PRIVATE IP: ${clientIp}, skipping geolocation`);
    } else {
      console.log(`[HONEYPOT] Access to fake route ${path} by IP: ${clientIp}`);
      try {
        const response = await axios.get(`http://ip-api.com/json/${clientIp}?fields=status,country,countryCode,regionName,city,lat,lon`);
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
        console.error('Erreur lors de la récupération géoloc IP:', error.message);
      }
    }

    console.log('Geo info:', geo);

    try {
      await Log.create({
        ip: clientIp,
        method: req.method,
        url: req.originalUrl,
        payload: req.body && Object.keys(req.body).length > 0 ? JSON.stringify(req.body) : '',
        detectedPatterns: [
          { name: 'Honeypot Access', severity: 'high' }
        ],
        highestSeverity: 'high',
        userAgent: req.headers['user-agent'] || '',
        geo
      });
    } catch (err) {
      console.error('Erreur lors de l\'enregistrement du log honeypot :', err);
    }

    res.status(403).send('Forbidden');
  });
});

module.exports = router;
