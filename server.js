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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway')
    ? { rejectUnauthorized: false } : false,
});

app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT NOT NULL,
        about TEXT DEFAULT 'Hai! Saya pakai EKK CHAT.',
        avatar_url TEXT,
        last_seen TIMESTAMPTZ DEFAULT NOW(),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        sender_id INT NOT NULL,
        recipient_id INT NOT NULL,
        content TEXT NOT NULL,
        read_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS statuses (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL,
        content TEXT NOT NULL,
        bg_color TEXT DEFAULT '#00A884',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS status_views (
        id SERIAL PRIMARY KEY,
        status_id INT NOT NULL,
        viewer_id INT NOT NULL,
        viewed_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(status_id, viewer_id)
      );
      CREATE TABLE IF NOT EXISTS calls (
        id SERIAL PRIMARY KEY,
        caller_id INT NOT NULL,
        recipient_id INT NOT NULL,
        type TEXT NOT NULL,
        status TEXT NOT NULL,
        duration INT DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS about TEXT DEFAULT \'Hai! Saya pakai EKK CHAT.\'');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen TIMESTAMPTZ DEFAULT NOW()');
    await pool.query('ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_at TIMESTAMPTZ');
    console.log('=== DB READY ===');
  } catch (e) {
    console.error('=== DB INIT ERROR ===', e.message);
  }
}
initDb();

function setAuthCookie(res, uid) {
  const token = jwt.sign({ uid }, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('ekk_token', token, {
    httpOnly: true, sameSite: 'none', secure: true,
    maxAge: 30 * 24 * 3600 * 1000, path: '/',
  });
}

function auth(req, res, next) {
  const t = req.cookies.ekk_token;
  if (!t) return res.status(401).json({ error: 'no_auth' });
  try {
    const p = jwt.verify(t, JWT_SECRET);
    req.uid = p.uid;
    next();
  } catch { res.status(401).json({ error: 'bad_token' }); }
}

app.get('/api/health', async (_req, res) => {
  let db = 'unknown';
  try { await pool.query('SELECT 1'); db = 'ok'; } catch (e) { db = 'error: ' + e.message; }
  res.json({ ok: true, db, time: Date.now() });
});

// ===== AUTH =====
app.post('/api/register', async (req, res) => {
  const { username, password, displayName } = req.body || {};
  if (!username || !password || !displayName) return res.status(400).json({ error: 'missing_field' });
  if (username.length < 3 || password.length < 6) return res.status(400).json({ error: 'too_short' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      'INSERT INTO users (username, password_hash, display_name) VALUES ($1,$2,$3) RETURNING id, username, display_name, about, avatar_url',
      [username.toLowerCase(), hash, displayName]
    );
    setAuthCookie(res, r.rows[0].id);
    res.json({ user: r.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: 'username_taken' });
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
    await pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [user.id]);
    setAuthCookie(res, user.id);
    res.json({ user: { id: user.id, username: user.username, display_name: user.display_name, about: user.about, avatar_url: user.avatar_url } });
  } catch (e) {
    res.status(500).json({ error: 'db_error', message: e.message });
  }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('ekk_token', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  const r = await pool.query('SELECT id, username, display_name, about, avatar_url FROM users WHERE id=$1', [req.uid]);
  if (!r.rows[0]) return res.status(401).json({ error: 'no_user' });
  res.json({ user: r.rows[0] });
});

app.patch('/api/me', auth, async (req, res) => {
  const { displayName, about, avatarUrl } = req.body || {};
  const updates = [];
  const values = [];
  let i = 1;
  if (displayName !== undefined) { updates.push(`display_name=$${i++}`); values.push(displayName); }
  if (about !== undefined) { updates.push(`about=$${i++}`); values.push(about); }
  if (avatarUrl !== undefined) { updates.push(`avatar_url=$${i++}`); values.push(avatarUrl); }
  if (!updates.length) return res.json({ ok: true });
  values.push(req.uid);
  const r = await pool.query(`UPDATE users SET ${updates.join(',')} WHERE id=$${i} RETURNING id, username, display_name, about, avatar_url`, values);
  res.json({ user: r.rows[0] });
});

// ===== USERS =====
app.get('/api/users', auth, async (req, res) => {
  const q = String(req.query.q || '').trim();
  try {
    const r = await pool.query(
      `SELECT id, username, display_name, about, avatar_url,
              CASE WHEN last_seen > NOW() - INTERVAL '2 minutes' THEN true ELSE false END AS is_online
       FROM users WHERE id != $1 AND (username ILIKE $2 OR display_name ILIKE $2)
       ORDER BY display_name LIMIT 30`,
      [req.uid, `%${q}%`]
    );
    res.json({ users: r.rows });
  } catch (e) { res.status(500).json({ error: 'db_error' }); }
});

// ===== MESSAGES =====
app.get('/api/messages/:userId', auth, async (req, res) => {
  const other = parseInt(req.params.userId, 10);
  if (!other) return res.status(400).json({ error: 'bad_id' });
  try {
    await pool.query(
      `UPDATE messages SET read_at=NOW() WHERE recipient_id=$1 AND sender_id=$2 AND read_at IS NULL`,
      [req.uid, other]
    );
    const r = await pool.query(
      `SELECT * FROM messages WHERE (sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1)
       ORDER BY created_at ASC LIMIT 300`,
      [req.uid, other]
    );
    res.json({ messages: r.rows });
  } catch (e) { res.status(500).json({ error: 'db_error' }); }
});

// ===== CHAT LIST =====
app.get('/api/chats', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT DISTINCT ON (other_id)
        other_id, last_msg, last_time, unread_count
      FROM (
        SELECT
          CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END AS other_id,
          content AS last_msg,
          created_at AS last_time,
          (SELECT COUNT(*) FROM messages m2
           WHERE m2.sender_id = CASE WHEN m.sender_id = $1 THEN m.recipient_id ELSE m.sender_id END
             AND m2.recipient_id = $1 AND m2.read_at IS NULL) AS unread_count
        FROM messages m
        WHERE sender_id = $1 OR recipient_id = $1
        ORDER BY created_at DESC
      ) sub
      ORDER BY other_id, last_time DESC
    `, [req.uid]);

    const otherIds = r.rows.map(x => x.other_id);
    if (!otherIds.length) return res.json({ chats: [] });

    const users = await pool.query(
      `SELECT id, username, display_name, about, avatar_url,
              CASE WHEN last_seen > NOW() - INTERVAL '2 minutes' THEN true ELSE false END AS is_online
       FROM users WHERE id = ANY($1)`,
      [otherIds]
    );
    const userMap = Object.fromEntries(users.rows.map(u => [u.id, u]));

    const chats = r.rows
      .map(row => ({ user: userMap[row.other_id], lastMessage: row.last_msg, lastTime: row.last_time, unread: parseInt(row.unread_count, 10) }))
      .filter(c => c.user)
      .sort((a, b) => new Date(b.lastTime) - new Date(a.lastTime));

    res.json({ chats });
  } catch (e) { console.error(e); res.status(500).json({ error: 'db_error' }); }
});

// ===== STATUSES =====
app.get('/api/statuses', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT s.id, s.user_id, s.content, s.bg_color, s.created_at,
             u.display_name, u.username, u.avatar_url,
             (SELECT COUNT(*) FROM status_views sv WHERE sv.status_id = s.id) AS view_count,
             EXISTS(SELECT 1 FROM status_views sv WHERE sv.status_id = s.id AND sv.viewer_id = $1) AS viewed_by_me
      FROM statuses s
      JOIN users u ON u.id = s.user_id
      WHERE s.created_at > NOW() - INTERVAL '24 hours'
      ORDER BY s.created_at DESC
    `, [req.uid]);
    res.json({ statuses: r.rows });
  } catch (e) { res.status(500).json({ error: 'db_error' }); }
});

app.post('/api/statuses', auth, async (req, res) => {
  const { content, bgColor } = req.body || {};
  if (!content || !content.trim()) return res.status(400).json({ error: 'empty' });
  try {
    const r = await pool.query(
      'INSERT INTO statuses (user_id, content, bg_color) VALUES ($1,$2,$3) RETURNING *',
      [req.uid, content.trim().slice(0, 700), bgColor || '#00A884']
    );
    io.emit('status:new');
    res.json({ status: r.rows[0] });
  } catch (e) { res.status(500).json({ error: 'db_error' }); }
});

app.post('/api/statuses/:id/view', auth, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO status_views (status_id, viewer_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [parseInt(req.params.id, 10), req.uid]
    );
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'db_error' }); }
});

app.delete('/api/statuses/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM statuses WHERE id=$1 AND user_id=$2', [parseInt(req.params.id, 10), req.uid]);
  res.json({ ok: true });
});

// ===== CALLS =====
app.get('/api/calls', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT c.*,
             CASE WHEN c.caller_id = $1 THEN c.recipient_id ELSE c.caller_id END AS other_id
      FROM calls c
      WHERE c.caller_id = $1 OR c.recipient_id = $1
      ORDER BY c.created_at DESC LIMIT 50
    `, [req.uid]);
    const otherIds = [...new Set(r.rows.map(x => x.other_id))];
    if (!otherIds.length) return res.json({ calls: [] });
    const users = await pool.query('SELECT id, username, display_name, avatar_url FROM users WHERE id = ANY($1)', [otherIds]);
    const userMap = Object.fromEntries(users.rows.map(u => [u.id, u]));
    res.json({
      calls: r.rows.map(c => ({
        ...c,
        user: userMap[c.other_id],
        direction: c.caller_id === req.uid ? 'outgoing' : 'incoming',
      })),
    });
  } catch (e) { res.status(500).json({ error: 'db_error' }); }
});

app.post('/api/calls', auth, async (req, res) => {
  const { recipientId, type, status, duration } = req.body || {};
  if (!recipientId || !type || !status) return res.status(400).json({ error: 'invalid' });
  try {
    const r = await pool.query(
      'INSERT INTO calls (caller_id, recipient_id, type, status, duration) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.uid, recipientId, type, status, duration || 0]
    );
    io.to(`user:${recipientId}`).emit('call:new');
    res.json({ call: r.rows[0] });
  } catch { res.status(500).json({ error: 'db_error' }); }
});

// ===== SOCKET.IO =====
io.use((socket, next) => {
  const cookieHeader = socket.handshake.headers.cookie || '';
  const m = cookieHeader.match(/ekk_token=([^;]+)/);
  if (!m) return next(new Error('no_auth'));
  try {
    socket.uid = jwt.verify(decodeURIComponent(m[1]), JWT_SECRET).uid;
    next();
  } catch { next(new Error('bad_token')); }
});

io.on('connection', (socket) => {
  socket.join(`user:${socket.uid}`);
  pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [socket.uid]).catch(() => {});

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
    } catch (e) { console.error('send error', e.message); }
  });

  socket.on('typing', ({ to, isTyping }) => {
    if (!to) return;
    io.to(`user:${to}`).emit('typing', { from: socket.uid, isTyping: !!isTyping });
  });

  socket.on('heartbeat', () => {
    pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [socket.uid]).catch(() => {});
  });

  socket.on('disconnect', () => {
    pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [socket.uid]).catch(() => {});
  });
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log('EKK CHAT listening on ' + PORT));