const mongoose = require('mongoose');

const detectedPatternSchema = new mongoose.Schema({
  name: { type: String, required: true },
  severity: { type: String, enum: ['low', 'medium', 'high'], required: true },
});

const geoSchema = new mongoose.Schema({
  country_short: String,
  country_long: String,
  region: String,
  city: String,
  latitude: Number,
  longitude: Number,
});

const logSchema = new mongoose.Schema({
  ip: { type: String, required: true, index: true },
  method: { type: String, required: true },
  url: { type: String, required: true },
  payload: String,
  detectedPatterns: [detectedPatternSchema],
  highestSeverity: { type: String, enum: ['low', 'medium', 'high'], default: 'low' },  // Nouveau champ
  userAgent: String,
  date: { type: Date, default: Date.now, index: true },
  geo: geoSchema,
});


// Export du modèle Mongoose
module.exports = mongoose.model('Log', logSchema);
