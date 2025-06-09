const { MongoClient } = require('mongodb');
const uri = 'mongodb://localhost:27017';
const dbName = 'blog_app';

async function logHoneypot(req, type) {
  const client = new MongoClient(uri);
  try {
    await client.connect();
    const db = client.db(dbName);
    const logs = db.collection('honeypot_logs');

    await logs.insertOne({
      type,
      ip: req.ip,
      headers: req.headers,
      body: req.body,
      path: req.originalUrl,
      timestamp: new Date()
    });
  } catch (err) {
    console.error('Erreur de log :', err);
  } finally {
    await client.close();
  }
}

module.exports = { logHoneypot };
