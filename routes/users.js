const express = require('express');
const router = express.Router();
const db = require('../services/db');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const authMiddleware = require('../ext/auth');

// Joi sheme za autentifikaciju
const signupSchema = Joi.object({
  name: Joi.string().min(3).max(100).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  passwordConfirmation: Joi.string().valid(Joi.ref('password')).required()
});

const signinSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});

// Joi shema za zadatke
const taskSchema = Joi.object({
  title: Joi.string().min(3).max(100).required(),
  description: Joi.string().max(500).allow('').optional(),
  priority: Joi.string().valid('low', 'medium', 'high').required()
});

// Registracija
router.get('/signup', (req, res) => res.render('users/signup'));

router.post('/signup', async (req, res) => {
  const { error } = signupSchema.validate(req.body);
  if (error) return res.render('users/signup', { error_validation: true });

  let conn;
  try {
    conn = await db.getConnection();
    await conn.query(`USE ${process.env.DB_NAME}`);
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const query = 'INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)';
    await conn.query(query, [req.body.name, req.body.email, hashedPassword]);
    res.render('users/signup', { success: true });
  } catch (error) {
    console.error('Greška pri registraciji:', error);
    res.render('users/signup', { error_database: true });
  } finally {
    if (conn) conn.release();
  }
});

// Prijava
router.get('/signin', (req, res) => res.render('users/signin'));

router.post('/signin', async (req, res) => {
  const { error } = signinSchema.validate(req.body);
  if (error) return res.render('users/signin', { error_validation: true });

  let conn;
  try {
    conn = await db.getConnection();
    await conn.query(`USE ${process.env.DB_NAME}`);
    const query = 'SELECT id, password_hash FROM users WHERE email = ?';
    const result = await conn.query(query, [req.body.email]);

    if (result.length === 0) return res.render('users/signin', { unknown_user: true });

    const hashedPasswordDb = result[0].password_hash;
    const compareResult = await bcrypt.compare(req.body.password, hashedPasswordDb);

    if (!compareResult) return res.render('users/signin', { invalid_password: true });

    res.cookie('express-app-user', req.body.email, {
      maxAge: 1209600000,
      httpOnly: true,
      sameSite: 'strict'
    });
    res.redirect('/profile');
  } catch (error) {
    console.error('Greška pri prijavi:', error);
    res.render('users/signin', { error_database: true });
  } finally {
    if (conn) conn.release();
  }
});

// Odjava
router.get('/signout', (req, res) => {
  res.clearCookie('express-app-user');
  res.redirect('/');
});

// Prikaz profila s zadacima
router.get('/profile', authMiddleware, async (req, res) => {
  let conn;
  try {
    conn = await db.getConnection();
    await conn.query(`USE ${process.env.DB_NAME}`);
    const userQuery = 'SELECT id, name, email FROM users WHERE email = ?';
    const userResult = await conn.query(userQuery, [req.userEmail]);

    if (userResult.length === 0) throw new Error('Korisnik nije pronađen');

    const tasksQuery = 'SELECT id, title, description, priority FROM tasks WHERE user_id = ?';
    const tasks = await conn.query(tasksQuery, [userResult[0].id]);

    res.render('users/profile', {
      title: 'Dnevni planer zadataka – Dino Ivančić',
      user: userResult[0],
      tasks
    });
  } catch (error) {
    console.error('Greška pri učitavanju profila:', error);
    res.render('error', { message: 'Greška pri učitavanju profila', error });
  } finally {
    if (conn) conn.release();
  }
});

// Dodavanje zadatka
router.post('/tasks', authMiddleware, async (req, res) => {
  const { error } = taskSchema.validate(req.body);
  if (error) return res.redirect('/profile?error=validation');

  let conn;
  try {
    conn = await db.getConnection();
    await conn.query(`USE ${process.env.DB_NAME}`);
    const userQuery = 'SELECT id FROM users WHERE email = ?';
    const userResult = await conn.query(userQuery, [req.userEmail]);

    const insertQuery = 'INSERT INTO tasks (user_id, title, description, priority) VALUES (?, ?, ?, ?)';
    await conn.query(insertQuery, [userResult[0].id, req.body.title, req.body.description, req.body.priority]);
    res.redirect('/profile');
  } catch (error) {
    console.error('Greška pri dodavanju zadatka:', error);
    res.render('error', { message: 'Greška pri dodavanju zadatka', error });
  } finally {
    if (conn) conn.release();
  }
});

// Brisanje zadatka
router.post('/tasks/delete/:id', authMiddleware, async (req, res) => {
  let conn;
  try {
    conn = await db.getConnection();
    await conn.query(`USE ${process.env.DB_NAME}`);
    const userQuery = 'SELECT id FROM users WHERE email = ?';
    const userResult = await conn.query(userQuery, [req.userEmail]);

    const deleteQuery = 'DELETE FROM tasks WHERE id = ? AND user_id = ?';
    await conn.query(deleteQuery, [req.params.id, userResult[0].id]);
    res.redirect('/profile');
  } catch (error) {
    console.error('Greška pri brisanju zadatka:', error);
    res.render('error', { message: 'Greška pri brisanju zadatka', error });
  } finally {
    if (conn) conn.release();
  }
});

module.exports = router;
