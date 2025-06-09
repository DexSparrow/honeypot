const mongoose = require('mongoose');

const portScanSchema = new mongoose.Schema({
  ip: String,
  port: Number,
  date: { type: Date, default: Date.now },
  type: { type: String, default: 'PORT_SCAN' },
});

module.exports = mongoose.model('PortScanLog', portScanSchema);
