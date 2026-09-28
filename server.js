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
const io = new Server(server, { maxHttpBufferSize: 10 * 1024 * 1024 });

const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-me';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('railway')
    ? { rejectUnauthorized: false } : false,
});
pool.on('error', e => console.error('POOL ERROR:', e.message));

app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

async function initDb() {
  try {
    await pool.query('SELECT 1');
    console.log('DB CONNECTED');
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
        recipient_id INT,
        group_id INT,
        content TEXT DEFAULT '',
        attachment JSONB,
        reply_to_id INT,
        deleted BOOLEAN DEFAULT FALSE,
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
      CREATE TABLE IF NOT EXISTS group_chats (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        created_by INT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS group_members (
        group_id INT NOT NULL,
        user_id INT NOT NULL,
        joined_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (group_id, user_id)
      );
    `);
    // migrations
    await pool.query('ALTER TABLE messages ADD COLUMN IF NOT EXISTS group_id INT');
    await pool.query('ALTER TABLE messages ADD COLUMN IF NOT EXISTS attachment JSONB');
    await pool.query('ALTER TABLE messages ADD COLUMN IF NOT EXISTS reply_to_id INT');
    await pool.query('ALTER TABLE messages ADD COLUMN IF NOT EXISTS deleted BOOLEAN DEFAULT FALSE');
    await pool.query('ALTER TABLE messages ALTER COLUMN recipient_id DROP NOT NULL');
    console.log('=== DB READY ===');
  } catch (e) { console.error('DB INIT ERROR:', e.message); }
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
  try { req.uid = jwt.verify(t, JWT_SECRET).uid; next(); }
  catch { res.status(401).json({ error: 'bad_token' }); }
}

const PUB_USER = 'id, username, display_name, about, avatar_url, last_seen';

app.get('/api/health', async (_req, res) => {
  let db = 'unknown';
  try { await pool.query('SELECT 1'); db = 'ok'; } catch (e) { db = 'error: ' + e.message; }
  res.json({ ok: true, db, time: Date.now() });
});

// ============ AUTH ============
app.post('/api/register', async (req, res) => {
  const { username, password, displayName } = req.body || {};
  if (!username || !password || !displayName) return res.status(400).json({ error: 'missing_field' });
  if (username.length < 3 || password.length < 6) return res.status(400).json({ error: 'too_short' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const r = await pool.query(
      `INSERT INTO users (username, password_hash, display_name) VALUES ($1,$2,$3) RETURNING ${PUB_USER}`,
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
    const u = r.rows[0];
    if (!u) return res.status(401).json({ error: 'invalid' });
    if (!await bcrypt.compare(password, u.password_hash)) return res.status(401).json({ error: 'invalid' });
    await pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [u.id]);
    setAuthCookie(res, u.id);
    res.json({ user: { id: u.id, username: u.username, display_name: u.display_name, about: u.about, avatar_url: u.avatar_url } });
  } catch (e) { res.status(500).json({ error: 'db_error', message: e.message }); }
});

app.post('/api/logout', (req, res) => { res.clearCookie('ekk_token', { path: '/' }); res.json({ ok: true }); });

app.get('/api/me', auth, async (req, res) => {
  const r = await pool.query(`SELECT ${PUB_USER} FROM users WHERE id=$1`, [req.uid]);
  if (!r.rows[0]) return res.status(401).json({ error: 'no_user' });
  res.json({ user: r.rows[0] });
});

app.patch('/api/me', auth, async (req, res) => {
  const { displayName, about, avatarUrl } = req.body || {};
  const ups = []; const vals = []; let i = 1;
  if (displayName !== undefined) { ups.push(`display_name=$${i++}`); vals.push(displayName); }
  if (about !== undefined) { ups.push(`about=$${i++}`); vals.push(about); }
  if (avatarUrl !== undefined) { ups.push(`avatar_url=$${i++}`); vals.push(avatarUrl); }
  if (!ups.length) return res.json({ ok: true });
  vals.push(req.uid);
  const r = await pool.query(`UPDATE users SET ${ups.join(',')} WHERE id=$${i} RETURNING ${PUB_USER}`, vals);
  res.json({ user: r.rows[0] });
});

// ============ USERS ============
app.get('/api/users', auth, async (req, res) => {
  const q = String(req.query.q || '').trim();
  try {
    const r = await pool.query(
      `SELECT ${PUB_USER}, (last_seen > NOW() - INTERVAL '2 minutes') AS is_online
       FROM users WHERE id != $1 AND (username ILIKE $2 OR display_name ILIKE $2)
       ORDER BY display_name LIMIT 30`, [req.uid, `%${q}%`]);
    res.json({ users: r.rows });
  } catch (e) { res.status(500).json({ error: 'db_error' }); }
});

// ============ MESSAGES ============
app.get('/api/messages/:userId', auth, async (req, res) => {
  const other = parseInt(req.params.userId, 10);
  if (!other) return res.status(400).json({ error: 'bad_id' });
  try {
    await pool.query(`UPDATE messages SET read_at=NOW() WHERE recipient_id=$1 AND sender_id=$2 AND read_at IS NULL AND group_id IS NULL`,
      [req.uid, other]);
    const r = await pool.query(
      `SELECT * FROM messages WHERE group_id IS NULL AND
        ((sender_id=$1 AND recipient_id=$2) OR (sender_id=$2 AND recipient_id=$1))
       ORDER BY created_at ASC LIMIT 300`, [req.uid, other]);
    res.json({ messages: r.rows });
  } catch (e) { res.status(500).json({ error: 'db_error' }); }
});

app.get('/api/messages/group/:groupId', auth, async (req, res) => {
  const gid = parseInt(req.params.groupId, 10);
  if (!gid) return res.status(400).json({ error: 'bad_id' });
  const m = await pool.query('SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2', [gid, req.uid]);
  if (!m.rows[0]) return res.status(403).json({ error: 'forbidden' });
  try {
    const r = await pool.query('SELECT * FROM messages WHERE group_id=$1 ORDER BY created_at ASC LIMIT 300', [gid]);
    res.json({ messages: r.rows });
  } catch (e) { res.status(500).json({ error: 'db_error' }); }
});

app.post('/api/messages/:id/delete', auth, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const r = await pool.query('SELECT sender_id FROM messages WHERE id=$1', [id]);
  if (!r.rows[0]) return res.status(404).json({ error: 'not_found' });
  if (r.rows[0].sender_id !== req.uid) return res.status(403).json({ error: 'forbidden' });
  await pool.query('UPDATE messages SET deleted=TRUE, content=\'\', attachment=NULL WHERE id=$1', [id]);
  const m = await pool.query('SELECT * FROM messages WHERE id=$1', [id]);
  io.to(`user:${req.uid}`).emit('message:deleted', { id });
  if (m.rows[0].recipient_id) io.to(`user:${m.rows[0].recipient_id}`).emit('message:deleted', { id });
  if (m.rows[0].group_id) io.to(`group:${m.rows[0].group_id}`).emit('message:deleted', { id });
  res.json({ ok: true });
});

// ============ CHAT LIST ============
app.get('/api/chats', auth, async (req, res) => {
  try {
    // Individual chats
    const indiv = await pool.query(`
      SELECT DISTINCT ON (other_id) other_id, last_msg, last_time, unread, attachment IS NOT NULL AS has_att
      FROM (
        SELECT CASE WHEN sender_id = $1 THEN recipient_id ELSE sender_id END AS other_id,
               content AS last_msg, created_at AS last_time, attachment,
               (SELECT COUNT(*) FROM messages m2
                WHERE m2.sender_id = CASE WHEN m.sender_id = $1 THEN m.recipient_id ELSE m.sender_id END
                  AND m2.recipient_id = $1 AND m2.read_at IS NULL AND m2.group_id IS NULL) AS unread
        FROM messages m
        WHERE (sender_id = $1 OR recipient_id = $1) AND group_id IS NULL AND deleted=FALSE
        ORDER BY created_at DESC
      ) sub ORDER BY other_id, last_time DESC`, [req.uid]);

    const otherIds = indiv.rows.map(x => x.other_id).filter(Boolean);
    let usersMap = {};
    if (otherIds.length) {
      const u = await pool.query(
        `SELECT ${PUB_USER}, (last_seen > NOW() - INTERVAL '2 minutes') AS is_online FROM users WHERE id = ANY($1)`,
        [otherIds]);
      u.rows.forEach(x => usersMap[x.id] = x);
    }
    const chats = indiv.rows
      .filter(r => usersMap[r.other_id])
      .map(r => ({
        kind: 'user', id: usersMap[r.other_id].id,
        user: usersMap[r.other_id],
        lastMessage: r.last_msg, lastTime: r.last_time,
        unread: parseInt(r.unread, 10), hasAtt: r.has_att
      }));

    // Group chats
    const groups = await pool.query(`
      SELECT g.id, g.name,
        (SELECT content FROM messages WHERE group_id=g.id AND deleted=FALSE ORDER BY created_at DESC LIMIT 1) AS last_msg,
        (SELECT created_at FROM messages WHERE group_id=g.id AND deleted=FALSE ORDER BY created_at DESC LIMIT 1) AS last_time
      FROM group_chats g
      JOIN group_members gm ON gm.group_id = g.id
      WHERE gm.user_id = $1`, [req.uid]);

    groups.rows.forEach(g => {
      chats.push({
        kind: 'group', id: g.id, name: g.name,
        lastMessage: g.last_msg, lastTime: g.last_time, unread: 0
      });
    });

    chats.sort((a, b) => new Date(b.lastTime || 0) - new Date(a.lastTime || 0));
    res.json({ chats });
  } catch (e) { console.error(e); res.status(500).json({ error: 'db_error' }); }
});

// ============ GROUPS ============
app.post('/api/groups', auth, async (req, res) => {
  const { name, memberIds } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: 'empty' });
  if (!Array.isArray(memberIds) || !memberIds.length) return res.status(400).json({ error: 'empty' });
  try {
    const g = await pool.query('INSERT INTO group_chats (name, created_by) VALUES ($1,$2) RETURNING id, name',
      [name.trim().slice(0, 60), req.uid]);
    const gid = g.rows[0].id;
    const allMembers = [...new Set([req.uid, ...memberIds.map(Number).filter(Boolean)])];
    for (const uid of allMembers) {
      await pool.query('INSERT INTO group_members (group_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [gid, uid]);
    }
    // system message
    const sysMsg = await pool.query(
      `INSERT INTO messages (sender_id, group_id, content) VALUES ($1,$2,$3) RETURNING *`,
      [req.uid, gid, `${name.trim()} dibuat`]
    );
    io.emit('group:new');
    res.json({ group: g.rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'db_error' }); }
});

app.get('/api/groups/:id/members', auth, async (req, res) => {
  const gid = parseInt(req.params.id, 10);
  const m = await pool.query('SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2', [gid, req.uid]);
  if (!m.rows[0]) return res.status(403).json({ error: 'forbidden' });
  const r = await pool.query(
    `SELECT u.${PUB_USER.replace(/, /g, ', u.').replace(/^/, '')} FROM users u
     JOIN group_members gm ON gm.user_id=u.id WHERE gm.group_id=$1`, [gid]);
  res.json({ members: r.rows });
});

// ============ STATUSES ============
app.get('/api/statuses', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT s.*, u.display_name, u.username, u.avatar_url,
             (SELECT COUNT(*) FROM status_views sv WHERE sv.status_id=s.id) AS view_count,
             EXISTS(SELECT 1 FROM status_views sv WHERE sv.status_id=s.id AND sv.viewer_id=$1) AS viewed_by_me
      FROM statuses s JOIN users u ON u.id=s.user_id
      WHERE s.created_at > NOW() - INTERVAL '24 hours'
      ORDER BY s.created_at DESC`, [req.uid]);
    res.json({ statuses: r.rows });
  } catch (e) { res.status(500).json({ error: 'db_error' }); }
});

app.post('/api/statuses', auth, async (req, res) => {
  const { content, bgColor } = req.body || {};
  if (!content || !content.trim()) return res.status(400).json({ error: 'empty' });
  try {
    const r = await pool.query(
      'INSERT INTO statuses (user_id, content, bg_color) VALUES ($1,$2,$3) RETURNING *',
      [req.uid, content.trim().slice(0, 700), bgColor || '#00A884']);
    io.emit('status:new');
    res.json({ status: r.rows[0] });
  } catch (e) { res.status(500).json({ error: 'db_error' }); }
});

app.post('/api/statuses/:id/view', auth, async (req, res) => {
  await pool.query('INSERT INTO status_views (status_id, viewer_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
    [parseInt(req.params.id, 10), req.uid]).catch(() => {});
  res.json({ ok: true });
});

app.delete('/api/statuses/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM statuses WHERE id=$1 AND user_id=$2', [parseInt(req.params.id, 10), req.uid]);
  res.json({ ok: true });
});

// ============ CALLS ============
app.get('/api/calls', auth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT c.*, CASE WHEN c.caller_id=$1 THEN c.recipient_id ELSE c.caller_id END AS other_id
      FROM calls c WHERE c.caller_id=$1 OR c.recipient_id=$1
      ORDER BY c.created_at DESC LIMIT 50`, [req.uid]);
    const ids = [...new Set(r.rows.map(x => x.other_id))];
    let um = {};
    if (ids.length) {
      const u = await pool.query(`SELECT ${PUB_USER} FROM users WHERE id = ANY($1)`, [ids]);
      u.rows.forEach(x => um[x.id] = x);
    }
    res.json({ calls: r.rows.map(c => ({ ...c, user: um[c.other_id], direction: c.caller_id === req.uid ? 'outgoing' : 'incoming' })) });
  } catch (e) { res.status(500).json({ error: 'db_error' }); }
});

app.post('/api/calls', auth, async (req, res) => {
  const { recipientId, type, status, duration } = req.body || {};
  if (!recipientId || !type || !status) return res.status(400).json({ error: 'invalid' });
  try {
    const r = await pool.query(
      'INSERT INTO calls (caller_id, recipient_id, type, status, duration) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [req.uid, recipientId, type, status, duration || 0]);
    io.to(`user:${recipientId}`).emit('call:new');
    res.json({ call: r.rows[0] });
  } catch { res.status(500).json({ error: 'db_error' }); }
});

// ============ SOCKET.IO ============
io.use((socket, next) => {
  const ch = socket.handshake.headers.cookie || '';
  const m = ch.match(/ekk_token=([^;]+)/);
  if (!m) return next(new Error('no_auth'));
  try { socket.uid = jwt.verify(decodeURIComponent(m[1]), JWT_SECRET).uid; next(); }
  catch { next(new Error('bad_token')); }
});

io.on('connection', async (socket) => {
  socket.join(`user:${socket.uid}`);
  const groups = await pool.query('SELECT group_id FROM group_members WHERE user_id=$1', [socket.uid]).catch(() => ({ rows: [] }));
  groups.rows.forEach(g => socket.join(`group:${g.group_id}`));
  pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [socket.uid]).catch(() => {});

  socket.on('message:send', async ({ to, groupId, content, attachment, replyTo }) => {
    const text = (content || '').trim().slice(0, 5000);
    if (!text && !attachment) return;
    try {
      let ins;
      if (groupId) {
        const m = await pool.query('SELECT 1 FROM group_members WHERE group_id=$1 AND user_id=$2', [groupId, socket.uid]);
        if (!m.rows[0]) return;
        ins = await pool.query(
          `INSERT INTO messages (sender_id, group_id, content, attachment, reply_to_id)
           VALUES ($1,$2,$3,$4,$5) RETURNING *`,
          [socket.uid, groupId, text, attachment || null, replyTo || null]);
        io.to(`group:${groupId}`).emit('message:new', ins.rows[0]);
      } else {
        if (!to) return;
        ins = await pool.query(
          `INSERT INTO messages (sender_id, recipient_id, content, attachment, reply_to_id)
           VALUES ($1,$2,$3,$4,$5) RETURNING *`,
          [socket.uid, to, text, attachment || null, replyTo || null]);
        io.to(`user:${to}`).emit('message:new', ins.rows[0]);
        io.to(`user:${socket.uid}`).emit('message:new', ins.rows[0]);
      }
    } catch (e) { console.error('send error', e.message); }
  });

  socket.on('typing', ({ to, groupId, isTyping }) => {
    if (groupId) io.to(`group:${groupId}`).except(`user:${socket.uid}`).emit('typing', { from: socket.uid, groupId, isTyping: !!isTyping });
    else if (to) io.to(`user:${to}`).emit('typing', { from: socket.uid, isTyping: !!isTyping });
  });

  socket.on('heartbeat', () => pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [socket.uid]).catch(() => {}));
  socket.on('disconnect', () => pool.query('UPDATE users SET last_seen=NOW() WHERE id=$1', [socket.uid]).catch(() => {}));
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log('EKK CHAT on ' + PORT));