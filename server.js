require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const authRoutes = require('./src/routes/auth');

if (!process.env.JWT_SECRET) {
  console.error('JWT_SECRET missing in environment');
  process.exit(1);
}

const app = express();
app.use(helmet());
app.use(cors({ origin: (process.env.FRONTEND_URL || '').split(',').filter(Boolean) }));
app.use(express.json());

app.get('/', (_req, res) => res.send('T2T backend running'));
app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));
app.use('/api/auth', authRoutes);

app.use((_req, res) => res.status(404).json({ message: 'Route not found' }));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`T2T backend on port ${PORT}`));
