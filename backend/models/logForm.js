const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
  ip: String,
  path: String,
  body: Object,
  reason: String,
  date: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Log', logSchema);
