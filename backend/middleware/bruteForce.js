/*const rateLimitMap = new Map(); // clé: IP, valeur: {count, lastAttempt}

const MAX_ATTEMPTS = 5;
const BLOCK_TIME = 15 * 60 * 1000; // 15 minutes

const { logAttack } = require('../utils/logger');

module.exports = (req, res, next) => {
  const ip = req.ip;
  const now = Date.now();

  let record = rateLimitMap.get(ip);

  if (!record) {
    rateLimitMap.set(ip, { count: 1, lastAttempt: now });
    return next();
  }

  if (record.count >= MAX_ATTEMPTS && now - record.lastAttempt < BLOCK_TIME) {
    logAttack(ip, req.originalUrl, 'Brute force blocked');
    return res.status(429).json({ message: 'Too many attempts, try later' });
  }

  if (now - record.lastAttempt > BLOCK_TIME) {
    // reset compteur après délai
    record.count = 1;
    record.lastAttempt = now;
  } else {
    record.count++;
    record.lastAttempt = now;
  }

  rateLimitMap.set(ip, record);
  next();
};
*/
const mongoose = require('mongoose');
const express = require('express');
const app = express();

// Modèle log d'attaque
const attackLogSchema = new mongoose.Schema({
  ip: String,
  path: String,
  method: String,
  timestamp: { type: Date, default: Date.now },
  reason: String,
  details: Object,
});
const AttackLog = mongoose.model('AttackLog', attackLogSchema);

// Simple store en mémoire pour brute force (IP => nb tentatives)
const bruteForceStore = new Map();
const MAX_ATTEMPTS = 5;
const BLOCK_TIME = 15 * 60 * 1000; // 15 min

function isBlocked(ip) {
  const entry = bruteForceStore.get(ip);
  if (!entry) return false;
  if (entry.blockedUntil && Date.now() < entry.blockedUntil) return true;
  return false;
}

function recordAttempt(ip) {
  const entry = bruteForceStore.get(ip) || { attempts: 0, blockedUntil: null };
  entry.attempts++;
  if (entry.attempts >= MAX_ATTEMPTS) {
    entry.blockedUntil = Date.now() + BLOCK_TIME;
  }
  bruteForceStore.set(ip, entry);
}

// Middleware honeypot sur /admin
app.use('/admin', async (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;

  if (isBlocked(ip)) {
    // IP bloquée => juste logguer
    await AttackLog.create({
      ip,
      path: req.originalUrl,
      method: req.method,
      reason: 'IP blocked for brute force',
      details: { attempts: bruteForceStore.get(ip).attempts },
    });
    return res.status(403).send('Access denied');
  }

  // Honeypot : on répond comme si la route existe mais on détecte les attaques
  if (req.method === 'POST' || req.method === 'GET') {
    // Exemple : détecter tentative de brute force en checkant un header ou body
    if (req.method === 'POST' && req.body && req.body.password) {
      // Simule un check password toujours faux
      recordAttempt(ip);

      await AttackLog.create({
        ip,
        path: req.originalUrl,
        method: req.method,
        reason: 'Brute force detected on honeypot',
        details: { passwordAttempt: req.body.password },
      });
      return res.status(401).send('Unauthorized');
    }
  }

  // Pour toutes les autres requêtes, on simule juste une 404 ou page vide
  res.status(404).send('Not found');
});
