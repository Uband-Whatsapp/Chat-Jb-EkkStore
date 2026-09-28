const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-me';

console.log('=== BOOTING EKK CHAT ===');
console.log('DATABASE_URL exists?', !!process.env.DATABASE_URL);
console.log('JWT_SECRET exists?', !!process.env.JWT_SECRET);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway')
    ? { rejectUnauthorized: false }
    : false,
});

pool.on('error', (err) => console.error('POOL ERROR:', err.message));

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

async function initDb() {
  try {
    console.log('Testing database connection...');
    const test = await pool.query('SELECT NOW() as now');
    console.log('DB CONNECTED at', test.rows[0].now);

    console.log('Creating users table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    console.log('users table OK');

    console.log('Creating messages table...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        sender_id INT NOT NULL,
        recipient_id INT NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
    console.log('messages table OK');

    console.log('=== DB READY ===');
  } catch (e) {
    console.error('=== DB INIT ERROR ===');
    console.error('message:', e.message);
    console.error('code:', e.code);
    console.error('detail:', e.detail);
    console.error('full:', e);
  }
}
initDb();

function setAuthCookie(res, uid) {
  const token = jwt.sign({ uid }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('ekk_token', token, {
    httpOnly: true,
    sameSite: 'none',
    secure: true,
    maxAge: 30 * 24 * 3600 * 1000,
    path: '/',
  });
}

function auth(req, res, next) {
  const t = req.cookies.ekk_token;
  if (!t) return res.status(401).json({ error: 'no_auth' });
  try {
    const p = jwt.verify(t, JWT_SECRET);
    req.uid = p.uid;
    next();
  } catch {
    res.status(401).json({ error: 'bad_token' });
  }
}

app.get('/api/health', async (req, res) => {
  let dbStatus = 'unknown';
  try {
    await pool.query('SELECT 1');
    dbStatus = 'ok';
  } catch (e) {
    dbStatus = 'error: ' + e.message;
  }
  res.json({ ok: true, db: dbStatus, time: Date.now() });
});

app.post('/api/register', async (req, res) => {
  const { username, password, displayName } = req.body || {};
  if (!username || !password || !displayName) {
    return res.status(400).json({ error: 'missing_field' });
  }
  if (username.length < 3 || password.length < 6) {
    return res.status(400).json({ error: 'too_short' });
  }
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      'INSERT INTO users (username, password_hash, display_name) VALUES ($1,$2,$3) RETURNING id, username, display_name',
      [username.toLowerCase(), hash, displayName]
    );
    const user = r.rows[0];
    setAuthCookie(res, user.id);
    res.json({ user });
  } catch (e) {
    console.error('REGISTER ERROR:', e.message, '| code:', e.code);
    if (e.code === '23505') {
      return res.status(400).json({ error: 'username_taken' });
    }
    res.status(500).json({ error: 'db_error', message: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing_field' });
  try {
    const r = await pool.query('SELECT * FROM users WHERE username=$1', [username.toLowerCase()]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'invalid' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid' });
    setAuthCookie(res, user.id);
    res.json({ user: { id: user.id, username: user.username, display_name: user.display_name } });
  } catch (e) {
    console.error('LOGIN ERROR:', e.message);
    res.status(500).json({ error: 'db_error', message: e.message });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('ekk_token', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, username, display_name FROM users WHERE id=$1', [req.uid]);
    if (!r.rows[0]) return res.status(401).json({ error: 'no_user' });
    res.json({ user: r.rows[0] });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.get('/api/users', auth, async (req, res) => {
  const q = String(req.query.q || '').trim();
  try {
    const r = await pool.query(
      `SELECT id, username, display_name FROM users
       WHERE id != $1 AND (username ILIKE $2 OR display_name ILIKE $2)
       ORDER BY display_name LIMIT 30`,
      [req.uid, `%${q}%`]
    );
    res.json({ users: r.rows });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.get('/api/messages/:userId', auth, async (req, res) => {
  const other = parseInt(req.params.userId, 10);
  if (!other) return res.status(400).json({ error: 'bad_id' });
  try {
    const r = await pool.query(
      `SELECT * FROM messages
       WHERE (sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1)
       ORDER BY created_at ASC LIMIT 300`,
      [req.uid, other]
    );
    res.json({ messages: r.rows });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

io.use((socket, next) => {
  const cookieHeader = socket.handshake.headers.cookie || '';
  const m = cookieHeader.match(/ekk_token=([^;]+)/);
  if (!m) return next(new Error('no_auth'));
  try {
    const p = jwt.verify(decodeURIComponent(m[1]), JWT_SECRET);
    socket.uid = p.uid;
    next();
  } catch {
    next(new Error('bad_token'));
  }
});

io.on('connection', (socket) => {
  console.log('socket connected', socket.uid);
  socket.join(`user:${socket.uid}`);

  socket.on('message:send', async ({ to, content }) => {
    if (!to || !content || typeof content !== 'string') return;
    const text = content.trim().slice(0, 5000);
    if (!text) return;
    try {
      const r = await pool.query(
        'INSERT INTO messages (sender_id, recipient_id, content) VALUES ($1,$2,$3) RETURNING *',
        [socket.uid, to, text]
      );
      const msg = r.rows[0];
      io.to(`user:${to}`).emit('message:new', msg);
      io.to(`user:${socket.uid}`).emit('message:new', msg);
    } catch (e) {
      console.error('send error', e.message);
    }
  });

  socket.on('typing', ({ to, isTyping }) => {
    if (!to) return;
    io.to(`user:${to}`).emit('typing', { from: socket.uid, isTyping: !!isTyping });
  });

  socket.on('disconnect', () => {
    console.log('socket disconnected', socket.uid);
  });
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log('EKK CHAT listening on port ' + PORT));