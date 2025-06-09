const express = require('express');
const router = express.Router();
const User = require('../models/user');
const checkHoneypot = require('../middleware/honeypotForm');
const bcrypt = require('bcrypt');

// Sign Up
router.post('/signup', checkHoneypot, async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    await User.create({ email, password: hashed });
    res.status(201).json({ message: 'Utilisateur inscrit' });
  } catch (err) {
    res.status(400).json({ error: 'Email déjà utilisé ou invalide' });
  }
});

// Login
router.post('/login', checkHoneypot, async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'Utilisateur inconnu' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Mot de passe incorrect' });

  res.json({ message: 'Connecté avec succès' });
});

// Reset password
router.post('/reset-password', checkHoneypot, async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const result = await User.updateOne({ email }, { password: hashed });
  if (result.modifiedCount === 0)
    return res.status(404).json({ error: 'Email non trouvé' });

  res.json({ message: 'Mot de passe mis à jour' });
});

module.exports = router;
