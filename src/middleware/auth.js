const jwt = require('jsonwebtoken');

// Protected routes ke liye: header "Authorization: Bearer <token>"
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Login required' });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET); // { id, role }
    next();
  } catch {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// Role-based access (FR-04): requireRole('Admin', 'Volunteer')
function requireRole(...roles) {
  return (req, res, next) =>
    roles.includes(req.user?.role)
      ? next()
      : res.status(403).json({ message: 'Access denied' });
}

module.exports = { requireAuth, requireRole };
