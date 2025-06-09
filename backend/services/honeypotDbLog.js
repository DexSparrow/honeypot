const { MongoClient } = require('mongodb');
const Tail = require('tail').Tail;
const path = '/var/log/mysql/honeypot.log';

const uri = process.env.MONGO_URI || 'mongodb://localhost:27017';
const dbName = 'honeypotdb';
const collectionName = 'honeypotdblog';

async function startHoneypotDB() {
  try {
    const client = new MongoClient(uri);
    await client.connect();
    console.log('Connecté à MongoDB (HoneypotDB)');

    const collection = client.db(dbName).collection(collectionName);
    const tail = new Tail(path);

    tail.on('line', async (line) => {
      try {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 4) return;

        const [timestamp, id, command, ...rest] = parts;
        if (command !== 'Connect') return;

        const userHost = rest.join(' ').split(' ')[0];
        if (!userHost.startsWith('admin@')) return;

        const doc = {
          timestamp: new Date(timestamp),
          connection_id: parseInt(id),
          command,
          details: rest.join(' ')
        };

        await collection.insertOne(doc);
        console.log('Connexion admin insérée:', doc);

      } catch (err) {
        console.error('Erreur lors du traitement:', err);
      }
    });

    tail.on('error', (err) => {
      console.error('Erreur lecture fichier:', err);
    });

  } catch (err) {
    console.error('Erreur MongoDB dans watcher:', err);
  }
}

module.exports = { startHoneypotDB };
