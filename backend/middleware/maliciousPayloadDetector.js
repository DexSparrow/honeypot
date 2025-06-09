const axios = require('axios');
const { detectMaliciousPatterns } = require('../utils/detector');

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

async function maliciousPayloadDetector(req, res, next) {
  try {
    let ip = req.headers['x-forwarded-for'] || req.ip || '';
    if (ip.includes(',')) {
      ip = ip.split(',')[0].trim();
    }
    ip = normalizeIp(ip);

    const payloadString = JSON.stringify({ ...req.body, ...req.query });
    const detection = detectMaliciousPatterns(payloadString);

    let ipInfo = null;
    if (detection.isMalicious) {
      if (!isPrivateIP(ip)) {
        try {
          const response = await axios.get(`http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,lat,lon`);
          if (response.data.status === 'success') {
            ipInfo = {
              country_short: response.data.countryCode,
              country_long: response.data.country,
              region: response.data.regionName,
              city: response.data.city,
              latitude: response.data.lat,
              longitude: response.data.lon,
            };
          }
        } catch (err) {
          console.error('Erreur récupération géoloc IP dans middleware :', err.message);
        }
      }

      const normalizedPatterns = detection.patterns.map(pattern => {
        if (typeof pattern === 'string') {
          return { name: pattern, severity: 'low' };
        }
        return {
          name: pattern.name || 'unknown',
          severity: pattern.severity || 'low',
        };
      });

      req.maliciousDetection = {
        isMalicious: detection.isMalicious,
        patterns: normalizedPatterns,
        payloadString,
        ip,
        ipInfo,
        method: req.method,
        url: req.originalUrl,
        userAgent: req.get('User-Agent') || '',
        date: new Date(),
      };

      if (process.env.NODE_ENV !== 'production') {
        console.log(`[ALERT] Malicious request detected from ${ip} on ${req.originalUrl}`);
        console.log('Patterns detected:', normalizedPatterns);
        console.log('Geo info:', ipInfo);
      }
    }
  } catch (err) {
    console.error('Error in maliciousPayloadDetector:', err);
  }

  next();
}

module.exports = maliciousPayloadDetector;
