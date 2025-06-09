const mongoose = require('mongoose');

const LogSchema = new mongoose.Schema({
  ip: String,
  user: String,
  query: String,
  timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model('DbLog', LogSchema);
