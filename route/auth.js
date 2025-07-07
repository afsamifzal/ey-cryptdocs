const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const db = require('../db/db');

router.post('/register', async (req, res) => {
  const { employee_id, email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.query(
      'INSERT INTO users (employee_id, email, password) VALUES (?, ?, ?)',
      [employee_id, email, hashedPassword],
      (err, result) => {
        if (err) {
          console.error(err);
          return res.status(500).send('Gagal daftar');
        }
        res.send('Pendaftaran berhasil');
      }
    );
  } catch (err) {
    res.status(500).send('Server error');
  }
});

module.exports = router;
