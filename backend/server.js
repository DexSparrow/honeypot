const app = require('./app');
const mongoose = require('mongoose');
const { startHoneypotPortScan } = require('./services/honeypotPortScanner');
const { startHoneypotDB } = require('./services/honeypotDbLog');

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/honeypotdb';

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log(' MongoDB connected');

    // Démarrage du serveur Express
    app.listen(PORT, () => {
      console.log(`Server started on port ${PORT}`);
    });

    // Lancer les honeypots de manière asynchrone
    setImmediate(() => {
      try {
        startHoneypotPortScan();
        startHoneypotDB();
        console.log('Honeypots démarrés');
      } catch (err) {
        console.error(' Erreur lors du démarrage des honeypots:', err);
      }
    });

  })
  .catch(err => {
    console.error('MongoDB connection error:', err);
  });
