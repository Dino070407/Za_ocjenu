const express = require('express');
const router = express.Router();
const authMiddleware = require('../ext/auth');
const db = require('../services/db'); // Dodaj ovu liniju

router.get('/', authMiddleware, async (req, res, next) => {
  let conn;
  try {
    conn = await db.getConnection(); // Linija 8 – ovdje se koristi db
    await conn.query(`USE ${process.env.DB_NAME}`);
    res.render('index', { title: 'Dnevni planer zadataka – Dino Ivančić' });
  } catch (error) {
    console.error('Greška:', error);
    next(error);
  } finally {
    if (conn) conn.release();
  }
});

module.exports = router;