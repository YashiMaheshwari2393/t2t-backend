const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const pool = require('../db');
const { requireAuth } = require('../middleware/auth');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { message: 'Too many attempts, try again later' },
});

const CARD_RE = /^[A-Za-z0-9-]{3,50}$/;

const publicUser = (u) => ({
  user_id: u.user_id,
  name: u.name,
  student_id: u.student_id,
  phone_no: u.phone_no,
  role: u.role,
});

async function audit(actorId, action, details) {
  try {
    await pool.execute(
      'INSERT INTO AuditLog (actor_id, action_type, target_entity, target_id, details) VALUES (?,?,?,?,?)',
      [actorId, action, 'User', actorId, details || null]
    );
  } catch (e) {
    console.error('audit failed:', e.message);
  }
}

const findByCard = async (cardId) => {
  const [rows] = await pool.execute('SELECT * FROM `User` WHERE student_id = ?', [cardId]);
  return rows[0];
};

// POST /api/auth/login  { name, student_id, phone_no }
//  - Smart Card ID pehli baar -> account + wallet ban jata hai (role Student)
//  - Pehle se hai -> mobile number match hona chahiye
router.post('/login', loginLimiter, async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const cardId = String(req.body?.student_id || '').trim().toUpperCase();
  const phone = String(req.body?.phone_no || '').replace(/\D/g, '').slice(-10); // +91 / spaces hata do

  if (name.length < 2 || name.length > 100) return res.status(400).json({ message: 'Enter a valid username' });
  if (!CARD_RE.test(cardId)) return res.status(400).json({ message: 'Enter a valid Smart Card ID' });
  if (!/^[6-9]\d{9}$/.test(phone)) return res.status(400).json({ message: 'Enter a valid 10-digit mobile number' });

  try {
    let user = await findByCard(cardId);
    let isNewUser = false;
    if (user && user.role === 'Admin')
      return res.status(403).json({ message: 'Admins must use the admin login' });

    if (!user) {
      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        const [r] = await conn.execute(
          "INSERT INTO `User` (name, student_id, phone_no, role) VALUES (?, ?, ?, 'Student')",
          [name, cardId, phone]
        );
        await conn.execute('INSERT INTO Wallet (user_id, balance) VALUES (?, 0)', [r.insertId]);
        await conn.commit();
        isNewUser = true;
      } catch (e) {
        await conn.rollback();
        if (e.code !== 'ER_DUP_ENTRY') throw e; // dono ne ek saath pehli baar login kiya -> neeche dobara fetch
      } finally {
        conn.release();
      }
      user = await findByCard(cardId);
    }

    if (!isNewUser && user.phone_no !== phone)
      return res.status(401).json({ message: 'Details do not match this Smart Card ID' });

    const token = jwt.sign({ id: user.user_id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1d',
    });
    await audit(user.user_id, isNewUser ? 'SIGNUP_LOGIN' : 'LOGIN');

    res.json({ token, user: publicUser(user), isNewUser });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/auth/me  (token chahiye)
router.get('/me', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT * FROM `User` WHERE user_id = ?', [req.user.id]);
    if (!rows[0]) return res.status(404).json({ message: 'User not found' });
    res.json({ user: publicUser(rows[0]) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
