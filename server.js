require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = Number(process.env.PORT || 3001);
app.set('trust proxy', 1);

// ---------------------------------------------------------------------------
// 100% file-based authentication. No MongoDB, Mongoose or external database.
// ---------------------------------------------------------------------------
const DATA_DIR = process.env.AUTH_DATA_DIR || path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'uk0wme';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ilobyou';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function ensureDataStore() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]\n', 'utf8');
  if (!fs.existsSync(SESSIONS_FILE)) fs.writeFileSync(SESSIONS_FILE, '{}\n', 'utf8');
}
function readJson(file, fallback) {
  ensureDataStore();
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { console.error(`Data read error (${path.basename(file)}):`, e.message); return fallback; }
}
function atomicWrite(file, value) {
  ensureDataStore();
  const temp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(temp, JSON.stringify(value, null, 2) + '\n', 'utf8');
  fs.renameSync(temp, file);
}
function readUsers() { const v = readJson(USERS_FILE, []); return Array.isArray(v) ? v : []; }
function writeUsers(users) { atomicWrite(USERS_FILE, users); }
function readSessions() { const v = readJson(SESSIONS_FILE, {}); return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }
function writeSessions(sessions) { atomicWrite(SESSIONS_FILE, sessions); }
function makeId() { return crypto.randomUUID(); }
function hashToken(token) { return crypto.createHash('sha256').update(`${SESSION_SECRET}:${token}`).digest('hex'); }
function findUser(username) {
  const key = String(username || '').trim().toLowerCase();
  return readUsers().find(u => String(u.username || '').toLowerCase() === key);
}
function findUserById(id) { return readUsers().find(u => u.id === String(id)); }
function hasUserExpired(user) {
  if (!user || user.role === 'admin' || !user.expires_at) return false;
  const t = new Date(user.expires_at).getTime();
  return Number.isFinite(t) && t <= Date.now();
}
function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    expiresAt: user.expires_at || null,
    isActive: user.is_active !== false,
    durationMinutes: Number(user.duration_minutes || 0),
    createdAt: user.created_at || null,
    lastLogin: user.last_login || null
  };
}
function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const key = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();
    try { out[key] = decodeURIComponent(value); } catch { out[key] = value; }
  });
  return out;
}
function cookieOptions() {
  const sameSite = String(process.env.COOKIE_SAMESITE || (process.env.NODE_ENV === 'production' ? 'lax' : 'lax')).toLowerCase();
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: ['lax','strict','none'].includes(sameSite) ? sameSite : 'lax',
    path: '/',
    maxAge: SESSION_TTL_MS
  };
}
function setAuthCookie(res, token) {
  const o = cookieOptions();
  const parts = [`cash_auth=${encodeURIComponent(token)}`, `Max-Age=${Math.floor(o.maxAge/1000)}`, 'Path=/', 'HttpOnly', `SameSite=${o.sameSite[0].toUpperCase()+o.sameSite.slice(1)}`];
  if (o.secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function clearAuthCookie(res) {
  const o = cookieOptions();
  const parts = ['cash_auth=', 'Max-Age=0', 'Path=/', 'HttpOnly', `SameSite=${o.sameSite[0].toUpperCase()+o.sameSite.slice(1)}`];
  if (o.secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function pruneSessions() {
  const sessions = readSessions();
  const now = Date.now();
  let changed = false;
  for (const [key, value] of Object.entries(sessions)) {
    if (!value || !value.expiresAt || new Date(value.expiresAt).getTime() <= now) { delete sessions[key]; changed = true; }
  }
  if (changed) writeSessions(sessions);
  return sessions;
}
function revokeUserSessions(userId, exceptTokenHash = null) {
  const sessions = pruneSessions();
  let changed = false;
  for (const [tokenHash, s] of Object.entries(sessions)) {
    if (s.userId === userId && tokenHash !== exceptTokenHash) { delete sessions[tokenHash]; changed = true; }
  }
  if (changed) writeSessions(sessions);
}
function createSession(user, deviceId) {
  const token = crypto.randomBytes(48).toString('base64url');
  const tokenHash = hashToken(token);
  // Exactly one active session per customer. Revoke first, then reload the
  // session store so a stale in-memory object cannot restore old sessions.
  revokeUserSessions(user.id);
  const sessions = pruneSessions();
  sessions[tokenHash] = {
    userId: user.id,
    username: user.username,
    role: user.role,
    deviceId: deviceId || null,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + SESSION_TTL_MS).toISOString()
  };
  writeSessions(sessions);
  return token;
}
function getBearerToken(req) {
  const header = String(req.headers.authorization || '');
  const match = header.match(/^Bearer\\s+(.+)$/i);
  return match ? match[1].trim() : '';
}
function getSession(req) {
  // Prefer an Authorization bearer token so a separately hosted frontend
  // does not depend on cross-site cookie behavior. Cookie auth remains supported.
  const token = getBearerToken(req) || parseCookies(req).cash_auth;
  if (!token) return null;
  const tokenHash = hashToken(token);
  const sessions = pruneSessions();
  const session = sessions[tokenHash];
  if (!session) return null;
  const user = findUserById(session.userId);
  if (!user) return null;
  if (hasUserExpired(user) || user.is_active === false) return null;
  // Every login gets one active session for the account. If another device
  // logs in, its new session replaces this token and this device becomes
  // invalid immediately on its next authenticated request.
  if (user.role !== 'admin' && user.active_session_id !== tokenHash) return null;
  return { token, tokenHash, session, user };
}
async function ensureAdmin() {
  const users = readUsers();
  const existing = users.find(u => String(u.username || '').toLowerCase() === ADMIN_USERNAME.toLowerCase());
  if (existing) {
    let changed = false;
    if (existing.role !== 'admin') { existing.role = 'admin'; changed = true; }
    if (existing.expires_at !== null) { existing.expires_at = null; changed = true; }
    if (existing.is_active === false) { existing.is_active = true; changed = true; }
    if (changed) writeUsers(users);
    return;
  }
  users.push({
    id: makeId(), username: ADMIN_USERNAME, password_hash: await bcrypt.hash(ADMIN_PASSWORD, 12),
    role: 'admin', is_active: true, expires_at: null, duration_minutes: 0,
    created_at: new Date().toISOString(), last_login: null, active_session_id: null
  });
  writeUsers(users);
  console.log(`Default admin created: ${ADMIN_USERNAME}`);
}

async function ensureDefaultUser() {
  const users = readUsers();
  const targetUsername = 'Ank';
  const existing = users.find(u => String(u.username || '').toLowerCase() === targetUsername.toLowerCase());
  
  if (existing) {
    let changed = false;
    if (Number(existing.duration_minutes || 0) < 43200) {
      existing.duration_minutes = 43200;
      changed = true;
    }
    if (existing.is_active === false) {
      existing.is_active = true;
      changed = true;
    }
    if (changed) writeUsers(users);
    return;
  }

  users.push({
    id: makeId(),
    username: targetUsername,
    password_hash: await bcrypt.hash('Ankit', 12),
    role: 'customer',
    is_active: true,
    expires_at: null,
    duration_minutes: 43200, // 30 days
    created_at: new Date().toISOString(),
    last_login: null,
    active_session_id: null
  });
  
  writeUsers(users);
  console.log(`Default customer user created: ${targetUsername} (30 days duration)`);
}

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (process.env.FRONTEND_URL && origin === process.env.FRONTEND_URL) return callback(null, true);
    if (/\.(vercel\.app|onrender\.com)$/.test(new URL(origin).hostname) || /^(localhost|127\.0\.0\.1)$/.test(new URL(origin).hostname)) return callback(null, true);
    return callback(null, true);
  },
  credentials: true
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.get('/health', (req, res) => res.json({ ok: true, authentication: 'file', database: 'none' }));
app.get('/api/health', (req, res) => res.json({ ok: true, authentication: 'file', database: 'none' }));

function requireAuth(req, res, next) {
  const auth = getSession(req);
  if (!auth) { clearAuthCookie(res); return res.status(401).json({ authenticated: false, error: 'Authentication required' }); }
  req.auth = auth;
  req.authUser = auth.user;
  next();
}
function requireAdmin(req, res, next) {
  const auth = getSession(req);
  if (!auth) { clearAuthCookie(res); return res.status(401).json({ authenticated: false, error: 'Authentication required' }); }
  if (auth.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden: Admin access required' });
  req.auth = auth;
  req.authUser = auth.user;
  next();
}
function deactivateIfExpired(user) {
  if (!hasUserExpired(user)) return false;
  const users = readUsers();
  const stored = users.find(u => u.id === user.id);
  if (stored && stored.is_active !== false) { stored.is_active = false; writeUsers(users); }
  revokeUserSessions(user.id);
  return true;
}

// ---------------------------------------------------------------------------
// Authentication API
// ---------------------------------------------------------------------------
app.post('/api/auth/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const deviceId = String(req.body?.deviceId || '').slice(0, 200);
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

    const user = findUser(username);
    if (!user) return res.status(401).json({ error: 'Invalid username or password.' });
    if (deactivateIfExpired(user)) return res.status(403).json({ error: 'Your access time has expired. Contact support to renew.' });
    if (user.is_active === false) return res.status(403).json({ error: 'Account is inactive.' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid username or password.' });

    const token = createSession(user, deviceId);
    const tokenHash = hashToken(token);
    const users = readUsers();
    const stored = users.find(u => u.id === user.id);
    if (!stored) return res.status(404).json({ error: 'User no longer exists.' });

    stored.last_login = new Date().toISOString();
    if (stored.role !== 'admin') {
      stored.active_session_id = tokenHash;
      // Expiry begins at first successful login, not when the admin creates the account.
      if (!stored.expires_at) {
        const minutes = Math.max(1, Number(stored.duration_minutes || 30));
        stored.expires_at = new Date(Date.now() + minutes * 60 * 1000).toISOString();
      }
    }
    writeUsers(users);
    setAuthCookie(res, token);
    res.set('Cache-Control', 'no-store');
    // Return the token as well as setting the cookie. The browser client stores
    // this token locally and sends it as Authorization, which is reliable when
    // the UI and API are on different HTTPS origins.
    return res.json({ success: true, message: 'Login successful', accessToken: token, user: publicUser(stored) });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Authentication service error.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  try {
    // Accept both the HttpOnly cookie and the bearer token used by the
    // frontend. This makes logout work consistently on separate devices and
    // separate frontend/API deployments.
    const token = getBearerToken(req) || parseCookies(req).cash_auth;
    if (token) {
      const tokenHash = hashToken(token);
      const sessions = pruneSessions();
      const session = sessions[tokenHash];
      if (session) {
        delete sessions[tokenHash];
        writeSessions(sessions);
        const users = readUsers();
        const user = users.find(u => u.id === session.userId);
        if (user && user.active_session_id === tokenHash) { user.active_session_id = null; writeUsers(users); }
      }
    }
    clearAuthCookie(res);
    res.json({ success: true });
  } catch (err) { clearAuthCookie(res); res.status(500).json({ error: 'Logout failed' }); }
});

app.get('/api/auth/status', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  const suppliedToken = getBearerToken(req) || parseCookies(req).cash_auth;
  const auth = getSession(req);
  if (!auth) {
    clearAuthCookie(res);

    // A previously valid customer token can become invalid because another
    // device logged in. Return a specific reason so the old device can show
    // a clear message instead of opening the mode-selection page.
    if (suppliedToken) {
      const tokenHash = hashToken(suppliedToken);
      const sessions = pruneSessions();
      const oldSession = sessions[tokenHash];
      if (oldSession) {
        const owner = readUsers().find(u => u.id === oldSession.userId);
        if (owner && owner.role !== 'admin' && owner.active_session_id !== tokenHash) {
          return res.json({ authenticated: false, reason: 'signed_in_elsewhere' });
        }
      }
    }
    return res.json({ authenticated: false });
  }
  if (deactivateIfExpired(auth.user)) { clearAuthCookie(res); return res.json({ authenticated: false, reason: 'expired' }); }
  return res.json({ authenticated: true, user: publicUser(auth.user) });
});

app.get('/api/users', requireAdmin, (req, res) => {
  const users = readUsers().sort((a,b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
  res.set('Cache-Control', 'no-store');
  res.json({ success: true, users: users.map(publicUser) });
});

app.post('/api/users', requireAdmin, async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    const duration = Number(req.body?.duration || 30);
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (username.length < 2 || username.length > 64) return res.status(400).json({ error: 'Username must be 2-64 characters.' });
    if (password.length < 1) return res.status(400).json({ error: 'Password is required.' });
    if (!Number.isFinite(duration) || duration <= 0 || duration > 525600) return res.status(400).json({ error: 'Invalid duration.' });
    const users = readUsers();
    if (users.some(u => String(u.username || '').toLowerCase() === username.toLowerCase())) return res.status(409).json({ error: 'Username already exists.' });
    const user = {
      id: makeId(), username, password_hash: await bcrypt.hash(password, 12), role: 'customer', is_active: true,
      expires_at: null, duration_minutes: Math.round(duration), created_at: new Date().toISOString(), last_login: null, active_session_id: null
    };
    users.push(user); writeUsers(users);
    res.status(201).json({ success: true, message: 'User created successfully', user: publicUser(user) });
  } catch (err) { console.error('Create user error:', err); res.status(500).json({ error: 'Internal server error' }); }
});

app.patch('/api/users/:id/extend', requireAdmin, (req, res) => {
  const days = Number(req.body?.days);
  if (!Number.isFinite(days) || days <= 0 || days > 3650) return res.status(400).json({ error: 'Invalid number of days' });
  const users = readUsers(); const user = users.find(u => u.id === req.params.id && u.role !== 'admin');
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!user.expires_at) user.duration_minutes = Number(user.duration_minutes || 30) + days * 24 * 60;
  else user.expires_at = new Date(Math.max(Date.now(), new Date(user.expires_at).getTime()) + days * 24 * 60 * 60 * 1000).toISOString();
  user.is_active = true; writeUsers(users);
  res.json({ success: true, newExpiry: user.expires_at || null });
});

app.patch('/api/users/:id', requireAdmin, async (req, res) => {
  const password = String(req.body?.password || '');
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const users = readUsers(); const user = users.find(u => u.id === req.params.id && u.role !== 'admin');
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.password_hash = await bcrypt.hash(password, 12); writeUsers(users);
  revokeUserSessions(user.id);
  user.active_session_id = null; writeUsers(users);
  res.json({ success: true, message: 'Password updated' });
});

app.delete('/api/users/expired', requireAdmin, (req, res) => {
  const users = readUsers(); const before = users.length;
  const expired = users.filter(u => u.role !== 'admin' && hasUserExpired(u));
  expired.forEach(u => revokeUserSessions(u.id));
  const kept = users.filter(u => u.role === 'admin' || !hasUserExpired(u));
  writeUsers(kept);
  res.json({ success: true, deletedCount: before - kept.length });
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
  const users = readUsers(); const index = users.findIndex(u => u.id === req.params.id && u.role !== 'admin');
  if (index < 0) return res.status(404).json({ error: 'User not found' });
  const [deleted] = users.splice(index, 1); writeUsers(users);
  revokeUserSessions(deleted.id);
  res.json({ success: true, message: 'User deleted' });
});

// ---------------------------------------------------------------------------
// Remaining application routes
// ---------------------------------------------------------------------------
// ============ TikTok Profile Lookup ============

const profileCache = new Map();
const PROFILE_CACHE_TTL = 10 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of profileCache) {
    if (now - v.ts > PROFILE_CACHE_TTL) profileCache.delete(k);
  }
}, 5 * 60 * 1000);

const normalizeCount = (value) => {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : 0;
  }
  if (typeof value === 'string') {
    const trimmed = value.trim().toUpperCase();
    const match = trimmed.match(/^([0-9]*\.?[0-9]+)\s*([KMB])?$/);
    if (match) {
      const base = Number(match[1]);
      if (!Number.isFinite(base)) return 0;
      const multipliers = { K: 1_000, M: 1_000_000, B: 1_000_000_000 };
      const multiplier = match[2] ? multipliers[match[2]] : 1;
      return Math.round(base * multiplier);
    }
    const numeric = Number(trimmed.replace(/[^0-9]/g, ''));
    return Number.isFinite(numeric) ? numeric : 0;
  }
  return 0;
};

const formatCount = (count) => {
  if (count >= 1_000_000_000) return (count / 1_000_000_000).toFixed(1) + 'B';
  if (count >= 1_000_000) return (count / 1_000_000).toFixed(1) + 'M';
  if (count >= 1_000) return (count / 1_000).toFixed(1) + 'K';
  return count.toString();
};

const TIKTOK_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

async function scrapeEmbedProfile(username) {
  try {
    const response = await fetch(`https://www.tiktok.com/embed/@${username}`, {
      headers: {
        'User-Agent': TIKTOK_UA,
        Accept: 'text/html',
        'Accept-Language': 'en-US,en;q=0.9',
      },
      signal: AbortSignal.timeout(10000),
    });

    if (!response.ok) return null;
    const html = await response.text();

    const match = html.match(/<script[^>]*id="__FRONTITY_CONNECT_STATE__"[^>]*>([\s\S]*?)<\/script>/i);
    if (!match || !match[1]) return null;

    const state = JSON.parse(match[1]);
    const sourceData = state?.source?.data || {};
    const sourceKey = Object.keys(sourceData).find((key) => key.toLowerCase().includes(username.toLowerCase()));
    const userInfo = sourceData[sourceKey]?.userInfo || {};

    let avatarRaw = userInfo.avatarThumbUrl || userInfo.avatarThumb || userInfo.avatarMedium || userInfo.avatarLarger || '';
    if (typeof avatarRaw === 'string') {
      avatarRaw = avatarRaw.replace(/\\u0026/g, '&');
    }

    const followerCount = Number(userInfo.followerCount) || 0;
    const followingCount = Number(userInfo.followingCount) || 0;
    const likesCount = Number(userInfo.heartCount) || 0;

    if (!avatarRaw && !userInfo.nickname) return null;

    return {
      username: userInfo.uniqueId || username,
      avatar: avatarRaw ? `/api/tiktok/avatar?url=${encodeURIComponent(avatarRaw)}` : '',
      nickname: userInfo.nickname || userInfo.uniqueId || username,
      followers: formatCount(followerCount),
      followerCount,
      following: formatCount(followingCount),
      followingCount,
      likes: formatCount(likesCount),
      likesCount,
    };
  } catch {
    return null;
  }
}

async function scrapeTikTokProfile(username) {
  const webId = Math.floor(Math.random() * 9_999_999_999_999).toString();
  const urls = [
    `https://www.tiktok.com/@${encodeURIComponent(username)}`,
    `https://www.tiktok.com/@${encodeURIComponent(username)}?lang=en`,
  ];

  let userDetail = null;
  let userStats = null;

  for (const url of urls) {
    try {
      const response = await fetch(url, {
        headers: {
          'User-Agent': TIKTOK_UA,
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Sec-Fetch-Dest': 'document',
          'Sec-Fetch-Mode': 'navigate',
          'Sec-Fetch-Site': 'none',
          'Sec-Fetch-User': '?1',
          Referer: 'https://www.google.com/',
          Cookie: 'tt_webid=' + webId,
        },
        signal: AbortSignal.timeout(9000),
      });

      const html = await response.text();
      if (html.includes('Please wait') || html.includes('wafchallengeid') || html.includes('SlardarWAF')) {
        continue;
      }

      const universalMatch = html.match(/<script[^>]*id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>([\s\S]*?)<\/script>/i);
      if (universalMatch && universalMatch[1]) {
        try {
          const data = JSON.parse(universalMatch[1]);
          const info = data?.__DEFAULT_SCOPE__?.['webapp.user-detail']?.userInfo;
          userDetail = info?.user || null;
          userStats = info?.stats || null;
          if (userDetail || userStats) break;
        } catch {}
      }

      const sigiMatch = html.match(/<script[^>]*id="SIGI_STATE"[^>]*>([\s\S]*?)<\/script>/i);
      if (sigiMatch && sigiMatch[1]) {
        try {
          const sigi = JSON.parse(sigiMatch[1]);
          userDetail = Object.values(sigi?.UserModule?.users || {})[0] || null;
          userStats = Object.values(sigi?.UserModule?.stats || {})[0] || null;
          if (userDetail || userStats) break;
        } catch {}
      }
    } catch {}
  }

  if (!userDetail && !userStats) return null;

  const followerCount = normalizeCount(userStats?.followerCount ?? userDetail?.followerCount ?? 0);
  const followingCount = normalizeCount(userStats?.followingCount ?? userDetail?.followingCount ?? 0);
  const likesCount = normalizeCount(userStats?.heartCount ?? userDetail?.heartCount ?? 0);

  const avatarRaw = userDetail?.avatarLarger || userDetail?.avatarMedium || userDetail?.avatarThumb || '';
  const avatar = avatarRaw ? `/api/tiktok/avatar?url=${encodeURIComponent(avatarRaw)}` : '';

  return {
    username: userDetail?.uniqueId || username,
    avatar,
    nickname: userDetail?.nickname || username,
    followers: formatCount(followerCount),
    followerCount,
    following: formatCount(followingCount),
    followingCount,
    likes: formatCount(likesCount),
    likesCount,
  };
}

async function buildTikTokProfile(username) {
  const [embed, scraped] = await Promise.all([
    scrapeEmbedProfile(username),
    scrapeTikTokProfile(username).catch(() => null),
  ]);

  const primary = (embed && embed.avatar) ? embed : (scraped && scraped.avatar) ? scraped : null;
  const secondary = primary === embed ? scraped : embed;

  if (primary) {
    if (secondary) {
      if (!primary.avatar && secondary.avatar) primary.avatar = secondary.avatar;
      if (secondary.nickname && secondary.nickname !== secondary.username) primary.nickname = secondary.nickname;
      if (!primary.followerCount && secondary.followerCount) {
        primary.followerCount = secondary.followerCount;
        primary.followers = secondary.followers;
      }
    }
    return primary;
  }

  const clean = String(username).trim().replace(/^@+/, '') || 'user';
  return {
    username: embed?.username || scraped?.username || clean,
    avatar: '',
    nickname: embed?.nickname || scraped?.nickname || clean,
    followers: embed?.followers || scraped?.followers || '0',
    followerCount: embed?.followerCount || scraped?.followerCount || 0,
    following: embed?.following || scraped?.following || '0',
    followingCount: embed?.followingCount || scraped?.followingCount || 0,
    likes: embed?.likes || scraped?.likes || '0',
    likesCount: embed?.likesCount || scraped?.likesCount || 0,
  };
}

app.get('/api/tiktok/profile/:username', async (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');

  const rawUsername = req.params.username || '';
  const cleanUsername = rawUsername.replace(/^@+/, '').trim();

  if (!cleanUsername || cleanUsername.length < 3) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  const cached = profileCache.get(cleanUsername.toLowerCase());
  if (cached && Date.now() - cached.ts < PROFILE_CACHE_TTL) {
    return res.json({ success: true, data: cached.data });
  }

  try {
    const profile = await buildTikTokProfile(cleanUsername);
    profileCache.set(cleanUsername.toLowerCase(), { data: profile, ts: Date.now() });
    return res.json({ success: true, data: profile });
  } catch (err) {
    console.error('TikTok profile fetch error:', err.message);
    return res.json({
      success: true,
      fallback: true,
      data: {
        username: cleanUsername,
        avatar: '',
        nickname: cleanUsername,
        followers: '0',
        followerCount: 0,
        following: '0',
        followingCount: 0,
        likes: '0',
        likesCount: 0,
      },
    });
  }
});

app.get('/api/tiktok/avatar', async (req, res) => {
  try {
    const url = req.query.url;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    const upstream = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        Referer: 'https://www.tiktok.com/',
      },
    });

    if (!upstream.ok) return res.status(502).json({ error: 'Failed to fetch avatar' });

    const contentType = upstream.headers.get('content-type') || 'image/jpeg';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public, max-age=3600');
    const arrayBuffer = await upstream.arrayBuffer();
    res.end(Buffer.from(arrayBuffer));
  } catch (err) {
    res.status(502).json({ error: 'Avatar proxy error', message: err?.message || 'unknown' });
  }
});

// ============ Cash App Profile Lookup ============

const CASHAPP_UAS = [
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
];

const cashappProfileCache = new Map();
const CASHAPP_CACHE_TTL = 10 * 60 * 1000;
const cashappNegativeCache = new Map();
const CASHAPP_NEG_CACHE_TTL = 30 * 1000;
const cashappInflight = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of cashappProfileCache) {
    if (now - v.ts > CASHAPP_CACHE_TTL) cashappProfileCache.delete(k);
  }
  for (const [k, v] of cashappNegativeCache) {
    if (now - v.ts > CASHAPP_NEG_CACHE_TTL) cashappNegativeCache.delete(k);
  }
}, 5 * 60 * 1000);

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function fetchCashAppHTML(cashtag, debugInfo) {
  const MAX_ROUNDS = 3;
  let lastErr = null;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    for (const ua of CASHAPP_UAS) {
      try {
        const response = await fetch(`https://cash.app/$${encodeURIComponent(cashtag)}`, {
          headers: {
            'User-Agent': ua,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
          },
          redirect: 'follow',
        });
        if (!response.ok) {
          lastErr = `status_${response.status}`;
          if (debugInfo) debugInfo.attempts.push({ round, ua: ua.slice(0, 30), status: response.status });
          if (response.status === 404) {
            if (debugInfo) debugInfo.lastErr = 'status_404';
            return null;
          }
          continue;
        }
        const html = await response.text();
        const hasJson = /var\s+profile\s*=\s*\{/.test(html);
        const hasTestid = /cashtags-profile-(title|subtitle)/.test(html);
        const hasFormatted = /formatted_cashtag/.test(html);
        const usable = hasJson || hasTestid || hasFormatted;
        if (debugInfo) debugInfo.attempts.push({
          round, ua: ua.slice(0, 30),
          status: response.status,
          bytes: html.length,
          hasJson, hasTestid, hasFormatted,
          snippet: html.slice(0, 400),
        });
        if (usable) return html;
        lastErr = 'unusable_html';
      } catch (err) {
        lastErr = err && err.message || 'fetch_err';
        if (debugInfo) debugInfo.attempts.push({ round, ua: ua.slice(0, 30), error: lastErr });
      }
    }
    if (round < MAX_ROUNDS - 1) {
      const backoff = 150 * Math.pow(3, round) + Math.floor(Math.random() * 100);
      await sleep(backoff);
    }
  }
  if (debugInfo) debugInfo.lastErr = lastErr;
  return null;
}

async function scrapeCashAppProfile(cashtag, debugInfo) {
  try {
    const html = await fetchCashAppHTML(cashtag, debugInfo);
    if (!html) return null;

    let fullName = '';
    let avatar = '';
    let displayTag = `$${cashtag}`;
    let initial = '';
    let accentColor = '';
    let isVerified = false;

    const profileJsonMatch = html.match(/var\s+profile\s*=\s*(\{[^;]+\});/);
    if (profileJsonMatch) {
      try {
        const profileData = JSON.parse(profileJsonMatch[1]);
        if (profileData.display_name) fullName = profileData.display_name;
        if (profileData.formatted_cashtag) displayTag = profileData.formatted_cashtag;
        if (profileData.avatar) {
          if (profileData.avatar.image_url) avatar = profileData.avatar.image_url;
          if (profileData.avatar.initial) initial = String(profileData.avatar.initial).slice(0, 2);
          if (profileData.avatar.accent_color) accentColor = String(profileData.avatar.accent_color);
        }
        if (typeof profileData.is_verified_account === 'boolean') {
          isVerified = profileData.is_verified_account;
        }
      } catch (e) {}
    }

    if (!fullName) {
      const titleMatch = html.match(/data-testid=["']cashtags-profile-title["'][^>]*>\s*(?:<[^>]+>\s*)*([^<]+?)\s*</i);
      if (titleMatch && titleMatch[1]) {
        const candidate = titleMatch[1].trim();
        if (candidate && candidate !== 'Pay me on Cash App') fullName = candidate;
      }
    }
    if (displayTag === `$${cashtag}`) {
      const subtitleMatch = html.match(/data-testid=["']cashtags-profile-subtitle["'][^>]*>\s*([^<]+?)\s*</i);
      if (subtitleMatch && subtitleMatch[1]) {
        const candidate = subtitleMatch[1].trim();
        if (candidate.startsWith('$')) displayTag = candidate;
      }
    }
    if (!avatar) {
      const imgMatch = html.match(/<img[^>]*alt=["']avatar image["'][^>]*src=["']([^"']+)["']/i)
        || html.match(/<img[^>]*src=["']([^"']+)["'][^>]*alt=["']avatar image["']/i);
      if (imgMatch) avatar = imgMatch[1];
    }
    if (!fullName) {
      const ogTitleMatch = html.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']+)["']/i);
      if (ogTitleMatch) {
        const title = ogTitleMatch[1].replace(/\s*[-|]\s*Cash App.*$/i, '').trim();
        if (title && title !== 'Pay me on Cash App') fullName = title;
      }
    }
    if (!avatar) {
      const franklinMatch = html.match(/["'](https:\/\/franklin-assets\.s3\.amazonaws\.com\/[^"']+)["']/i);
      if (franklinMatch) avatar = franklinMatch[1];
    }
    if (!avatar) {
      const squarecdnMatch = html.match(/["'](https:\/\/cash-images-f\.squarecdn\.com\/[^"']+)["']/i);
      if (squarecdnMatch) avatar = squarecdnMatch[1];
    }

    const hasRealData = !!(fullName || avatar || initial);
    if (!hasRealData) return null;

    return {
      username: cashtag,
      fullName: fullName || `$${cashtag}`,
      displayTag,
      avatar: avatar ? `/api/cashapp/avatar?url=${encodeURIComponent(avatar)}` : '',
      initial: initial || (fullName ? fullName.trim().charAt(0).toUpperCase() : cashtag.charAt(0).toUpperCase()),
      accentColor: accentColor || '',
      isVerified,
    };
  } catch (err) {
    return null;
  }
}

app.get('/api/cashapp/profile/:cashtag', async (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.set('X-Cashapp-Lookup-Build', '2026-06-12-bulletproof');

  const rawCashtag = req.params.cashtag || '';
  const cleanCashtag = rawCashtag.replace(/^\$+/, '').trim();

  if (!cleanCashtag || cleanCashtag.length < 1) {
    return res.status(400).json({ error: 'Invalid cashtag' });
  }

  const skipCache = req.query.nocache === '1';
  const wantDebug = req.query.debug === '1';
  const debugInfo = wantDebug ? { attempts: [], lastErr: null } : null;
  const key = cleanCashtag.toLowerCase();

  if (!skipCache) {
    const cached = cashappProfileCache.get(key);
    if (cached && Date.now() - cached.ts < CASHAPP_CACHE_TTL) {
      return res.json({ success: true, data: cached.data, cached: true });
    }
    const neg = cashappNegativeCache.get(key);
    if (neg && Date.now() - neg.ts < CASHAPP_NEG_CACHE_TTL) {
      return res.json({ success: false, notFound: true, cached: true });
    }
  }

  if (!cashappInflight.has(key)) {
    cashappInflight.set(key, scrapeCashAppProfile(cleanCashtag, debugInfo).finally(() => {
      setTimeout(() => cashappInflight.delete(key), 50);
    }));
  }

  try {
    const profile = await cashappInflight.get(key);
    if (profile) {
      cashappProfileCache.set(key, { data: profile, ts: Date.now() });
      cashappNegativeCache.delete(key);
      const out = { success: true, data: profile };
      if (debugInfo) out.debug = debugInfo;
      return res.json(out);
    } else {
      cashappNegativeCache.set(key, { ts: Date.now() });
      const out = { success: false, notFound: true };
      if (debugInfo) out.debug = debugInfo;
      return res.json(out);
    }
  } catch (err) {
    const out = { success: false, error: err?.message || 'fetch_error' };
    if (debugInfo) out.debug = debugInfo;
    return res.json(out);
  }
});

app.get('/api/cashapp/avatar', async (req, res) => {
  try {
    const url = req.query.url;
    if (!url) return res.status(400).json({ error: 'Missing url' });

    const upstream = await fetch(url, {
      headers: {
        'User-Agent': CASHAPP_UAS[0],
        'Referer': 'https://cash.app/',
      },
    });

    if (!upstream.ok) return res.status(502).json({ error: 'Failed to fetch avatar' });

    const contentType = upstream.headers.get('content-type') || 'image/jpeg';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public, max-age=3600');
    const arrayBuffer = await upstream.arrayBuffer();
    res.end(Buffer.from(arrayBuffer));
  } catch (err) {
    res.status(502).json({ error: 'Cash App avatar proxy error', message: err?.message || 'unknown' });
  }
});

app.get('/site.webmanifest', (req, res) => {
  res.type('application/manifest+json');
  res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
  res.sendFile(path.join(__dirname, 'site.webmanifest'));
});

app.get('/sw.js', (req, res) => {
  res.type('application/javascript');
  res.setHeader('Cache-Control', 'public, max-age=0, must-revalidate');
  res.setHeader('Service-Worker-Allowed', '/');
  res.sendFile(path.join(__dirname, 'sw.js'));
});

app.use(express.static(path.join(__dirname), {
  setHeaders(res, filePath) {
    if (/\/(icon-192|icon-512|apple-touch-icon)\.png$/.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    }
  }
}));

// Export for Vercel serverless
module.exports = app;

// Start server (for local development)
if (require.main === module) {
  ensureAdmin()
    .then(() => ensureDefaultUser())
    .then(() => {
      app.listen(PORT, () => {
        console.log(`🚀 Cash Clone server running on http://localhost:${PORT}`);
        console.log(`🔐 Authentication: JSON file storage (MongoDB not required)`);
        console.log(`👤 Admin username: ${ADMIN_USERNAME}`);
        console.log(`📁 User data file: ${USERS_FILE}`);
      });
    })
    .catch((err) => {
      console.error('❌ Failed to initialize authentication storage:', err);
      process.exit(1);
    });
}
