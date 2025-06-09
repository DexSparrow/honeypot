module.exports = (req, res, next) => {
  const honeypot = req.body.honeypot || '';
  if (honeypot.trim() !== '') {
    console.log(`[BOT DETECTED] IP: ${req.ip}, Path: ${req.originalUrl}, Honeypot value: "${honeypot}"`);

    // Stocke dans une collection MongoDB (si besoin)
    const Log = require('../models/Log');
    Log.create({
      ip: req.ip,
      path: req.originalUrl,
      body: req.body,
      reason: 'Honeypot triggered'
    });

    return res.status(403).json({ error: 'Bot detected' });
  }
  next();
};
