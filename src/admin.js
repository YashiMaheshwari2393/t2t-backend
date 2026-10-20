const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const pool = require('../db');
const { requireAuth, requireRole } = require('../middleware/auth');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { message: 'Too many attempts, try again later' },
});

const ID_RE = /^[A-Za-z0-9-]{3,50}$/;
const normName = (s) => String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');

// POST /api/admin/login  { name, admin_id, phone_no }
// Admin pehle se DB me hona chahiye (role = 'Admin'). Yahan naya account NAHI banta.
router.post('/login', loginLimiter, async (req, res) => {
  const name = normName(req.body?.name);
  const adminId = String(req.body?.admin_id || '').trim().toUpperCase();
  const phone = String(req.body?.phone_no || '').replace(/\D/g, '').slice(-10);

  if (name.length < 2) return res.status(400).json({ message: 'Enter a valid name' });
  if (!ID_RE.test(adminId)) return res.status(400).json({ message: 'Enter a valid Admin ID' });
  if (!/^[6-9]\d{9}$/.test(phone)) return res.status(400).json({ message: 'Enter a valid 10-digit mobile number' });

  try {
    const [rows] = await pool.execute("SELECT * FROM `User` WHERE student_id = ? AND role = 'Admin'", [adminId]);
    const admin = rows[0];
    // Teeno cheezein match honi chahiye. Error generic rakha hai taaki ID guess na ho sake.
    if (!admin || admin.phone_no !== phone || normName(admin.name) !== name)
      return res.status(401).json({ message: 'Invalid admin details' });

    const token = jwt.sign({ id: admin.user_id, role: 'Admin' }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '1d',
    });

    try {
      await pool.execute(
        'INSERT INTO AuditLog (actor_id, action_type, target_entity, target_id, details) VALUES (?,?,?,?,?)',
        [admin.user_id, 'ADMIN_LOGIN', 'User', admin.user_id, null]
      );
    } catch (e) {
      console.error('audit failed:', e.message);
    }

    res.json({
      token,
      admin: { user_id: admin.user_id, name: admin.name, admin_id: admin.student_id, phone_no: admin.phone_no, role: admin.role },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// Neeche ke sab routes sirf Admin token se chalenge
router.use(requireAuth, requireRole('Admin'));

// GET /api/admin/me
router.get('/me', async (req, res) => {
  try {
    const [rows] = await pool.execute('SELECT user_id, name, student_id, phone_no, role FROM `User` WHERE user_id = ?', [req.user.id]);
    if (!rows[0]) return res.status(404).json({ message: 'Admin not found' });
    const a = rows[0];
    res.json({ admin: { user_id: a.user_id, name: a.name, admin_id: a.student_id, phone_no: a.phone_no, role: a.role } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /api/admin/dashboard  -> overview numbers
router.get('/dashboard', async (_req, res) => {
  try {
    const [roleRows] = await pool.execute('SELECT role, COUNT(*) AS count FROM `User` GROUP BY role');
    const [[wallet]] = await pool.execute('SELECT COALESCE(SUM(balance),0) AS total_ecocoins FROM Wallet');
    const [recent] = await pool.execute(
      `SELECT a.action_type, a.timestamp, u.name, u.role
         FROM AuditLog a JOIN \`User\` u ON u.user_id = a.actor_id
        ORDER BY a.log_id DESC LIMIT 10`
    );
    const users = { Student: 0, Volunteer: 0, Shopkeeper: 0, Admin: 0 };
    roleRows.forEach((r) => (users[r.role] = Number(r.count)));
    res.json({ users, total_ecocoins: Number(wallet.total_ecocoins), recent_activity: recent });
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;
