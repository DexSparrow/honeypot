const express = require('express');
const path = require('path');
const mongoose = require('mongoose');

const maliciousPayloadDetector = require('./middleware/maliciousPayloadDetector');
const fakeRoutes = require('./routes/fakeRoutes');
const logsRoutes = require('./routes/logsRoutes');
const analyzeRoute = require('./routes/analyze');
const authRoutes = require('./routes/auth');


const app = express();

const cors = require('cors');
app.use(cors()); // Allow all origins — for development
app.set('trust proxy', true);

// Middleware express pour parser JSON + URL encoded
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes d’auth (login/signup/reset) avec honeypot
app.use('/', authRoutes);

// Middleware gestion d'erreur JSON malformé
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    console.warn(`[JSON PARSE ERROR] Malformed JSON from IP: ${req.ip}, URL: ${req.originalUrl}`);
    return res.status(400).json({ error: 'JSON malformé ou body vide' });
  }
  next(err);
});

// Middleware detection requêtes suspectes
app.use(maliciousPayloadDetector);

// Routes pièges
app.use(fakeRoutes);

// Routes logs (dashboard/admin)
app.use('/api', analyzeRoute);
app.use('/api/logs', logsRoutes);

/*
// Décommente uniquement si tu as buildé ton frontend React
app.use(express.static(path.join(__dirname, '../frontend-client/build')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend-client/build/index.html'));
});
*/

module.exports = app;
