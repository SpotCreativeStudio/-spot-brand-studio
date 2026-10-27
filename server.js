'use strict' 

function capitalizeAfterSentences(text) {
  if (!text || typeof text !== 'string') return text;
  let result = text.replace(/^([a-zäöå])/, function(c){ return c.toUpperCase(); });
  result = result.replace(/([.!?]\s+)([a-zäöå])/g, function(m, sep, letter){ return sep + letter.toUpperCase(); });
  return result;
}
const express = require('express')
const path = require('path')
const fs = require('fs')
const crypto = require('crypto')
let nodemailer = null
try { nodemailer = require('nodemailer') } catch (e) {}
const app = express()
app.set('trust proxy', 1)
const PORT = process.env.PORT || 3000
const UNAME = process.env.APP_USERNAME || 'Spot'
const UPASS = process.env.APP_PASSWORD || 'SpotSpot1234!'
const sessions = {}
const { Pool } = require('pg')
let _authPool = null
function getAuthPool() { if (!_authPool) _authPool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }); return _authPool }
async function ensureAuthTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)") }
async function ensureSessionsTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS app_sessions (token TEXT PRIMARY KEY, data JSONB, created_at BIGINT)") }
function persistSession(token, data) {
  ensureSessionsTable()
    .then(function(){ return getAuthPool().query('INSERT INTO app_sessions (token,data,created_at) VALUES ($1,$2,$3) ON CONFLICT (token) DO UPDATE SET data=$2', [token, JSON.stringify(data), Date.now()]) })
    .catch(function(e){ console.error('[session] persist error:', e.message) })
}
function dropSession(token) {
  ensureSessionsTable()
    .then(function(){ return getAuthPool().query('DELETE FROM app_sessions WHERE token=$1', [token]) })
    .catch(function(){})
}
async function restoreSessions() {
  try {
    await ensureSessionsTable()
    const cutoff = Date.now() - 1000 * 60 * 60 * 24 * 7
    await getAuthPool().query('DELETE FROM app_sessions WHERE created_at < $1', [cutoff])
    const r = await getAuthPool().query('SELECT token, data FROM app_sessions')
    r.rows.forEach(function(row){ sessions[row.token] = row.data })
    console.log('[session] restored ' + r.rows.length + ' sessions')
  } catch (e) { console.error('[session] restore error:', e.message) }
}
async function ensureUsersTable() {
  await getAuthPool().query("CREATE TABLE IF NOT EXISTS app_users (username TEXT PRIMARY KEY, password TEXT, role TEXT, first_name TEXT, last_name TEXT)")
  await getAuthPool().query("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS email TEXT")
  await getAuthPool().query("ALTER TABLE app_users ADD COLUMN IF NOT EXISTS workspace TEXT DEFAULT 'spot'")
  await getAuthPool().query("UPDATE app_users SET workspace='spot' WHERE workspace IS NULL")
  const r = await getAuthPool().query("SELECT COUNT(*) FROM app_users")
  if (parseInt(r.rows[0].count, 10) === 0) {
    await getAuthPool().query("INSERT INTO app_users (username,password,role,first_name,last_name,workspace) VALUES ($1,$2,$3,$4,$5,'spot'),($6,$7,$8,$9,$10,'spot'),($11,$12,$13,$14,$15,'spot')", [
      'admin', hashPassword('Spot1234!'), 'admin', 'Anna', 'Andersson',
      'redaktor', hashPassword('Spot1234!'), 'redaktor', 'Erik', 'Eriksson',
      'granskare', hashPassword('Spot1234!'), 'granskare', 'Gustav', 'Granberg'
    ])
  }
}
async function ensureAdvocacyTable() {
  await getAuthPool().query("CREATE TABLE IF NOT EXISTS advocacy_shares (id SERIAL PRIMARY KEY, workspace TEXT, username TEXT, action TEXT, post_id TEXT, created_at BIGINT)")
}
app.post('/api/advocacy/log-share', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { postId, action } = req.body || {}
    await ensureAdvocacyTable()
    await getAuthPool().query('INSERT INTO advocacy_shares (workspace, username, action, post_id, created_at) VALUES ($1,$2,$3,$4,$5)', [s.workspace || 'spot', s.u || '', action || 'share', String(postId||''), Date.now()])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.get('/api/advocacy/leaderboard', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureUsersTable()
    await ensureAdvocacyTable()
    const r = await getAuthPool().query(
      "SELECT u.username, u.first_name, u.last_name, COALESCE(a.shared,0)::int AS shared " +
      "FROM app_users u " +
      "LEFT JOIN (SELECT username, COUNT(*) AS shared FROM advocacy_shares WHERE workspace=$1 GROUP BY username) a ON a.username = u.username " +
      "WHERE u.workspace=$1 " +
      "ORDER BY shared DESC, u.username ASC " +
      "LIMIT 5",
      [s.workspace || 'spot']
    )
    res.json({ advocates: r.rows })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
async function getUserByUsername(username) {
  try { await ensureUsersTable(); const r = await getAuthPool().query("SELECT * FROM app_users WHERE username=$1", [username]); return r.rows[0] || null } catch (e) { console.error('[auth] getUserByUsername error:', e.message); return null }
}
async function getUserByEmail(email) {
  try { await ensureUsersTable(); const r = await getAuthPool().query("SELECT * FROM app_users WHERE lower(email)=$1", [String(email || '').trim().toLowerCase()]); return r.rows[0] || null } catch (e) { console.error('[auth] getUserByEmail error:', e.message); return null }
}
// ---- Lösenord: sparas som scrypt-hash (salt + hash), aldrig i klartext ----
// Gamla lösenord i klartext fungerar fortfarande och uppgraderas till hash vid nästa inloggning.
function hashPassword(pw) { const salt = crypto.randomBytes(16).toString('hex'); return 'scrypt$' + salt + '$' + crypto.scryptSync(String(pw), salt, 64).toString('hex') }
function isHashedPassword(stored) { return typeof stored === 'string' && stored.indexOf('scrypt$') === 0 }
function verifyPassword(pw, stored) {
  if (stored == null || pw == null) return false
  if (!isHashedPassword(stored)) return String(pw) === String(stored)
  const parts = stored.split('$'); if (parts.length !== 3) return false
  const want = Buffer.from(parts[2], 'hex'), got = crypto.scryptSync(String(pw), parts[1], 64)
  return want.length === got.length && crypto.timingSafeEqual(want, got)
}
async function getPassword() { try { await ensureAuthTable(); const r = await getAuthPool().query("SELECT value FROM app_settings WHERE key='password'"); return (r.rows[0] && r.rows[0].value) || UPASS } catch (e) { console.error('[auth] getPassword error:', e.message); return UPASS } }
async function setPassword(pw) { try { await ensureAuthTable(); const r = await getAuthPool().query("INSERT INTO app_settings (key,value) VALUES ('password',$1) ON CONFLICT (key) DO UPDATE SET value=$1", [hashPassword(pw)]); console.log('[auth] setPassword ok, rowCount:', r.rowCount) } catch (e) { console.error('[auth] setPassword error:', e.message) } }
const resetTokens = {}
function makeResetToken(username) { const t = crypto.randomBytes(24).toString('hex'); resetTokens[t] = { exp: Date.now() + 30 * 60 * 1000, username: username || null }; return t }
function validResetToken(t) { const e = resetTokens[t]; return !!e && e.exp > Date.now() }
function getMailer() { if (!nodemailer) return null; if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) return null; return nodemailer.createTransport({ host: process.env.SMTP_HOST, port: +(process.env.SMTP_PORT || 587), secure: process.env.SMTP_PORT === '465', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }, connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 10000 }) }
async function sendAppMail({ to, subject, text, html, fromName, replyTo, attachments }) {
  const key = process.env.RESEND_API_KEY
  if (!key) return false
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.assign({ from: (fromName ? String(fromName).replace(/[<>"\r\n]/g, '') : 'spot. Brand Studio') + ' <noreply@platform.spotstudio.se>', to: [to], subject, text, html }, replyTo ? { reply_to: replyTo } : {}, attachments && attachments.length ? { attachments } : {}))
    })
    const data = await r.json().catch(() => ({}))
    if (!r.ok) { console.error('[resend] error:', JSON.stringify(data)); return false }
    return true
  } catch (e) { console.error('[resend] exception:', e.message); return false }
}
app.use(express.json({ limit: '20mb' }))
app.use(express.urlencoded({ extended: true }))
const _TPL = { 'tpl-studio.png': '4.png', 'tpl-case-hallanning.png': '5.png', 'tpl-case-gardsstyling.png': '7.png', 'tpl-louisiana.png': '6.png' }
const FAVICON_PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAIAAAD8GO2jAAAE2ElEQVR42u1Wa2xURRQ+Z2bu3bu3u9tdyrYFti1gbStStFYggS5RCVGIwUhREiPRBEMiRoMgPv6YQIgx8Y8kakyqJmpiDCEQENFglPoAhGqgppIW2qbPbWnZbXfv7t3d+5jjj8UCDSRG4ZecZCaZmfN9X3LOmZmDh6qegltpDG6x3Ra4LfC/FECG1wggInIGiICInCFj01yRMeQMOQfEaUQFLPIrEJLkmPmrPfmTaq2byQEi2a6dNMl2mCIAGRDInI2cO4bpmpZjZJEzJjhIQsbIla5pkZROKuuaea6pyBAAyXHnb1rNGEt3x7hHAQJRXD8v1HgnSBI+Tfi8iVOdibbz0rKRs2BDdbKjb9ajS8MrFjHBuz84ZPaP8SLNNXPCr8+M1hdVlRUvqJxs7x3c+6Nr2mo4MP+5NbVb13Xs/Jx5ROrcoDVhsNrt6yfP9owcOT249yfjwvCidzarM/xF1bOjh3fX73627OFGktT36VF/bcXyAztFQHeMrDcSnrfpEbP/YuzgiaEDx6u3rI0e3u0pD5oD44nTnUCUaOsaa2130lnkjCXaukaOnsqNxPPjycEvW08077Qn05numBLQvXNKJtq6Rr8+PXm25/cte/TZJXMeW2ZNGAt3PZM41Zls73XM/MXvz7Suek2vLF3csk3aDhEVEkCSLid54Zsbm/btKl+zRK8q5UWacX6YCOx01ozFs0PxTO+oWuJXQ34rkbbTWb0iHGy4I9hQPdneq5YEAEgrDeXHk3+88XHJkroZ99e46dy0ohI9Hx2JPL68ojkKAMaF4fN79g/t/4VxjogoGKqCXEmSmMpQcNvIFs0tV4M+FExaNnIubUcJ6GOt7dKyixfOTfeOXFuzyNpfbTl635ZjD+04s+3DfDzV+N6LM5fdXQgfEAARIJLjaqUhoampjj57Ii00NXBXlZu1kDEgQsGclJmPG46Zh6n6RABEshzGOCcpU50DfZ9990PT1uGvTpatbHDsHDAkSYDIFGFPpstXL3bM3KVfzxldg/kJo277etfMk5QoONmuCOh2KhM//qfi00lKICJHypzlKQ2yutc3AIC0HBRcKS6Sjpv4rYsLlRypFOvgytxoIrCgsubl5rM7Whwj6+bsMy+9H47W37vneSedtZMZJ5OLrGvq/eTbTP9FIkLGuK5xjzKnuWnl8Xf5Kxs3hx+8RwsH/bWRiieiqY7+oX0/M0WJrFvur4kYPTE9Eq5+YW1vy5GBL46pxUVMFcmOvnhbZ+WGB8pXNXKP4q+tyMbisYMn1JA/N5IoWVoXjtZnBsYRYfbqJbjPv1avCGvlIQDIjSRyowkl5LfiqRXfvMU9ysmn3/bOKsn0jVoJQw35yJUAgJzZKRMZ+msiTFWysUtW3BA+jQjIdlDhWtmMbCwubUcrDwnPzICdzOTHk4DAFKEEfUAEAIXZHBizJ9JM4VPsAECuVAI6SUp3x4iIqUL4tELhoyKAyBwYY6rgmmqNJwW5EjnjuqdAWlgCAKoCFcFVhXs95LpT7FMaAMA09TLq72sFRIDAPAoQAREqQlw5uAos/F6mClS48HvJcaa9o1fp0PU2L4+CA16n8SJAzpSADgh2yiRHAv7770Fc78sAcmX+UhIAkPP/wn4DAQBAQEXcMAg3QeBmUN/uKv6h/QVNLGWbh4CtIwAAAABJRU5ErkJggg==';
const FAVICON_PNG_BUF = Buffer.from(FAVICON_PNG_B64, 'base64');
// ---- Feedback: skickas till hello@spotstudio.se med kunden som avsändarnamn och svara-adress ----
async function ensureFeedbackTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS feedback (id SERIAL PRIMARY KEY, username TEXT, email TEXT, workspace TEXT, type TEXT, message TEXT, view TEXT, user_agent TEXT, emailed BOOLEAN, created_at BIGINT)") }
function browserName(ua) {
  ua = String(ua || '')
  let b = 'Okänd webbläsare', m
  if ((m = ua.match(/Edg\/(\d+)/))) b = 'Edge ' + m[1]
  else if ((m = ua.match(/OPR\/(\d+)/))) b = 'Opera ' + m[1]
  else if ((m = ua.match(/Firefox\/(\d+)/))) b = 'Firefox ' + m[1]
  else if ((m = ua.match(/Chrome\/(\d+)/))) b = 'Chrome ' + m[1]
  else if ((m = ua.match(/Version\/(\d+).*Safari/))) b = 'Safari ' + m[1]
  let os = ''
  if (/iPhone|iPad/.test(ua)) os = 'iOS'
  else if (/Android/.test(ua)) os = 'Android'
  else if (/Windows/.test(ua)) os = 'Windows'
  else if (/Mac OS X/.test(ua)) os = 'Mac'
  else if (/Linux/.test(ua)) os = 'Linux'
  return os ? b + ' · ' + os : b
}
function slugBase(s) { return String(s || '').toLowerCase().normalize('NFC') }
function escHtml(v) { return String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])) }
app.post('/api/feedback', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { type = 'Övrigt', message = '', view = '', screenshot = null } = req.body || {}
    const msg = String(message).trim().slice(0, 5000)
    if (!msg) return res.status(400).json({ error: 'Skriv något först' })
    const kind = ['Bugg', 'Idé', 'Övrigt'].includes(type) ? type : 'Övrigt'
    let email = null
    try { const u = await getUserByUsername(s.u); email = (u && u.email) || null } catch (e) {}
    if (!email && s.u && String(s.u).includes('@')) email = s.u
    const name = ((s.firstName || '') + ' ' + (s.lastName || '')).trim() || s.u || 'Okänd användare'
    const ws = s.workspace || 'spot'
    const ua = String(req.headers['user-agent'] || '')
    const when = new Date().toLocaleString('sv-SE', { timeZone: 'Europe/Stockholm' })
    const subject = '[Feedback · ' + kind + '] ' + name + ' (' + ws + ')'
    const rows = [['Från', name + (email ? ' <' + email + '>' : '')], ['Workspace', ws], ['Roll', s.role || ''], ['Typ', kind], ['Vy', view], ['Tid', when], ['Webbläsare', browserName(ua)]]
    const text = msg + '\n\n---\n' + rows.map(r => r[0] + ': ' + r[1]).join('\n')
    const html = '<div style="font-family:Arial,sans-serif;font-size:14px;color:#111">' +
      '<div style="font-size:11px;font-weight:bold;color:#888;text-transform:uppercase;letter-spacing:.05em;margin:0 0 6px">Meddelande</div>' +
      '<p style="white-space:pre-wrap;margin:0 0 16px;padding:12px 14px;background:#f6f6f6;border-radius:8px">' + escHtml(msg) + '</p>' +
      '<table style="font-size:12px;color:#555;border-top:1px solid #eee;padding-top:8px">' +
      rows.map(r => '<tr><td style="padding:2px 12px 2px 0;font-weight:bold">' + escHtml(r[0]) + '</td><td>' + escHtml(r[1]) + '</td></tr>').join('') +
      '</table></div>'
    const attachments = []
    if (screenshot && typeof screenshot === 'string') {
      const m = screenshot.match(/^data:(image\/(png|jpeg|jpg|webp|gif));base64,(.+)$/)
      if (m && m[3].length < 10 * 1024 * 1024) attachments.push({ filename: 'skarmdump.' + (m[2] === 'jpeg' ? 'jpg' : m[2]), content: m[3] })
    }
    const to = process.env.FEEDBACK_EMAIL || 'hello@spotstudio.se'
    const emailed = await sendAppMail({ to, subject, text, html, fromName: name + ' (via spot.)', replyTo: email || undefined, attachments })
    try { await ensureFeedbackTable(); await getAuthPool().query('INSERT INTO feedback (username,email,workspace,type,message,view,user_agent,emailed,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)', [s.u || '', email, ws, kind, msg, String(view).slice(0, 100), ua.slice(0, 300), emailed, Date.now()]) } catch (e) { console.error('[feedback] db:', e.message) }
    if (!emailed) console.error('[feedback] mejlet kunde inte skickas (saknas RESEND_API_KEY?) – sparat i databasen')
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
// ---- Bildlagring (förberedelse för bildkarusell) ----
// Bilder sparas som egna rader i stället för base64 inuti inlägget.
// POST /api/images  { dataUrl }  ->  { id, url: '/img/<id>' }
// GET  /img/:id                    ->  själva bilden (bara för samma arbetsyta)
async function ensureImagesTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS stored_images (id TEXT PRIMARY KEY, workspace TEXT, username TEXT, mime TEXT, data BYTEA, bytes INTEGER, created_at BIGINT)") }
// Klickbara kolumner i posts: link (öppnar inlägget) och image_url (öppnar bilden)
async function ensurePostLinkColumns() { await getAuthPool().query('ALTER TABLE posts ADD COLUMN IF NOT EXISTS link TEXT'); await getAuthPool().query('ALTER TABLE posts ADD COLUMN IF NOT EXISTS image_url TEXT') }
function postLinks(id, post, origin) { const img = (post && typeof post.imageUrl === 'string' && post.imageUrl.indexOf('http') === 0) ? post.imageUrl : null; return { link: origin + '/p/' + encodeURIComponent(id), image_url: img } }
// Sparar en data:-bild i stored_images och returnerar en länk (/img/<id>). Samma bild ger samma id, så inga dubbletter.
async function storeDataUrlImage(dataUrl, workspace, username, origin) {
  const m = String(dataUrl || '').match(/^data:(image\/(png|jpeg|jpg|webp|gif));base64,(.+)$/)
  if (!m) return null
  const buf = Buffer.from(m[3], 'base64')
  if (buf.length > 8 * 1024 * 1024) return null
  await ensureImagesTable()
  const id = crypto.createHash('sha256').update(String(workspace || 'spot')).update(buf).digest('hex').slice(0, 24)
  await getAuthPool().query('INSERT INTO stored_images (id,workspace,username,mime,data,bytes,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING', [id, workspace || 'spot', username || '', m[1], buf, buf.length, Date.now()])
  return (origin || '') + '/img/' + id
}
app.post('/api/images', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const m = String((req.body || {}).dataUrl || '').match(/^data:(image\/(png|jpeg|jpg|webp|gif));base64,(.+)$/)
    if (!m) return res.status(400).json({ error: 'Ogiltig bild' })
    const buf = Buffer.from(m[3], 'base64')
    if (buf.length > 8 * 1024 * 1024) return res.status(400).json({ error: 'Bilden är för stor (max 8 MB)' })
    await ensureImagesTable()
    const id = crypto.randomBytes(12).toString('hex')
    await getAuthPool().query('INSERT INTO stored_images (id,workspace,username,mime,data,bytes,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)', [id, s.workspace || 'spot', s.u || '', m[1], buf, buf.length, Date.now()])
    res.json({ id, url: '/img/' + id })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
// Engångsflytt: gör om gamla inlägg med base64-bild till länkar (/img/<id>). Bara Spot-admin. Ändrar inte created_at.
app.post('/api/admin/migrate-post-images', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.realWorkspace || s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    const pool = getAuthPool()
    await pool.query('CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, data JSONB, created_at TIMESTAMPTZ DEFAULT NOW())')
    await ensurePostLinkColumns()
    const r = await pool.query('SELECT id, data FROM posts')
    let converted = 0, savedBytes = 0
    for (const row of r.rows) {
      const post = row.data || {}
      const before = JSON.stringify(post).length
      for (const k of ['imageUrl', 'aiImageUrl']) {
        if (typeof post[k] === 'string' && post[k].indexOf('data:') === 0) {
          const u = await storeDataUrlImage(post[k], post.workspace || 'spot', post.author || '', 'https://' + req.get('host'))
          if (u) post[k] = u
        }
      }
      const _l = postLinks(row.id, post, 'https://' + req.get('host'))
      await pool.query('UPDATE posts SET data=$1, link=$2, image_url=$3 WHERE id=$4', [JSON.stringify(post), _l.link, _l.image_url, row.id])
      converted++; savedBytes += before - JSON.stringify(post).length
    }
    res.json({ ok: true, converted, savedMB: +(savedBytes / 1048576).toFixed(2) })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
// Visa ett inlägg via länk: /p/<id> (inloggad, samma arbetsyta eller Spot-admin)
app.get('/p/:id', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const r = await getAuthPool().query('SELECT data, created_at FROM posts WHERE id=$1', [req.params.id])
    if (!r.rows.length) return res.status(404).send('Inlägget finns inte')
    const p = r.rows[0].data || {}
    const home = s.realWorkspace || s.workspace || 'spot'
    if ((p.workspace || 'spot') !== (s.workspace || 'spot') && !(home === 'spot' && s.role === 'admin')) return res.status(404).send('Inlägget finns inte')
    const img = p.imageUrl || p.aiImageUrl || ''
    const tags = (p.hashtags || []).map(t => '#' + String(t).replace(/^#/, '')).join(' ')
    const meta = [['Arbetsyta', p.workspace], ['Status', p.status], ['Kanal', p.channel], ['Författare', p.author], ['Skapad', p.createdAt || r.rows[0].created_at], ['Schemalagd', p.scheduledAt], ['Id', req.params.id]].filter(m => m[1])
    res.setHeader('Content-Type', 'text/html; charset=utf-8')
    res.send('<!doctype html><html lang="sv"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' + escHtml(p.title || 'Inlägg') + '</title>' +
      '<style>body{font-family:system-ui,Arial,sans-serif;background:#f5f5f7;margin:0;padding:24px;color:#111}.c{max-width:640px;margin:0 auto;background:#fff;border-radius:14px;box-shadow:0 4px 20px rgba(0,0,0,.08);overflow:hidden}img{display:block;width:100%}.b{padding:20px 24px}h1{font-size:22px;margin:0 0 10px}p{white-space:pre-wrap;line-height:1.5;margin:0 0 12px}.t{color:#b31e59;font-size:14px}table{font-size:12px;color:#555;border-top:1px solid #eee;margin-top:16px;padding-top:10px}td{padding:2px 12px 2px 0}td:first-child{font-weight:600}</style></head><body><div class="c">' +
      (img && img.indexOf('data:') !== 0 ? '<img src="' + escHtml(img) + '" alt="">' : (img ? '<img src="' + img + '" alt="">' : '')) +
      '<div class="b"><h1>' + escHtml(p.title || '') + '</h1><p>' + escHtml(p.content || '') + '</p>' + (tags ? '<div class="t">' + escHtml(tags) + '</div>' : '') +
      '<table>' + meta.map(m => '<tr><td>' + escHtml(m[0]) + '</td><td>' + escHtml(m[1]) + '</td></tr>').join('') + '</table></div></div></body></html>')
  } catch (e) { res.status(500).send('Fel: ' + escHtml(e.message)) }
})
app.get('/img/:id', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if (!/^[a-f0-9]{24}$/.test(req.params.id)) return res.status(400).end()
    await ensureImagesTable()
    const r = await getAuthPool().query('SELECT mime, data, workspace FROM stored_images WHERE id=$1', [req.params.id])
    if (!r.rows.length) return res.status(404).end()
    const row = r.rows[0]
    const home = s.realWorkspace || s.workspace || 'spot'
    if (row.workspace !== (s.workspace || 'spot') && !(home === 'spot' && s.role === 'admin')) return res.status(404).end()
    res.setHeader('Content-Type', row.mime)
    res.setHeader('Cache-Control', 'private, max-age=31536000, immutable')
    res.send(row.data)
  } catch (e) { res.status(500).end() }
})
app.get('/favicon.ico', (req, res) => {
  res.set('Content-Type', 'image/png');
  res.send(FAVICON_PNG_BUF);
});

app.get('/assets/:f', (req, res) => { const f = _TPL[req.params.f] || req.params.f; if (f.indexOf('..') !== -1 || f.indexOf('/') !== -1) return res.status(400).end(); const p = path.join(__dirname, 'assets', f); if (fs.existsSync(p)) return res.sendFile(p); res.status(404).end() })
function passwordError(pw) { pw = String(pw || ''); if (pw.length < 6 || !/[A-ZÅÄÖ]/.test(pw) || !/[^A-Za-z0-9ÅÄÖåäö]/.test(pw)) return 'Lösenordet måste vara minst 6 tecken och innehålla minst en versal och ett specialtecken'; return null }
function makeToken() { return crypto.randomBytes(32).toString('hex') }
function getToken(req) { const c = req.headers.cookie || ''; const p = c.split(';').map(x => x.trim()).find(x => x.startsWith('spot_session=')); return p ? p.split('=')[1] : null }
function auth(req, res, next) { if (sessions[getToken(req)]) return next(); if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' }); res.redirect('/login') }
app.get('/login', (_req, res) => res.send(LOGIN_HTML))
app.post('/login', async (req, res) => {
  const { username, password } = req.body
  const identifier = String(username || '')
  const u = (await getUserByUsername(identifier)) || (identifier.includes('@') ? await getUserByEmail(identifier) : null)
  if (u && verifyPassword(password, u.password)) {
    if (!isHashedPassword(u.password)) { try { await getAuthPool().query('UPDATE app_users SET password=$1 WHERE username=$2', [hashPassword(password), u.username]) } catch (e) {} }
    const t = makeToken()
    sessions[t] = { u: u.username, role: u.role, firstName: u.first_name, lastName: u.last_name, workspace: u.workspace || 'spot' }
    persistSession(t, sessions[t])
    res.setHeader('Set-Cookie', 'spot_session=' + t + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + (60*60*24*7))
    return res.redirect('/')
  }
  const recoveryEmail = process.env.APP_RECOVERY_EMAIL
  const isMainAdmin = identifier === UNAME || (recoveryEmail && identifier.trim().toLowerCase() === recoveryEmail.trim().toLowerCase())
  const _mainPw = isMainAdmin ? await getPassword() : null
  if (isMainAdmin && verifyPassword(password, _mainPw)) {
    if (!isHashedPassword(_mainPw)) await setPassword(password)
    const t = makeToken()
    sessions[t] = { u: UNAME, role: 'admin', firstName: process.env.APP_USER_FIRSTNAME || 'Spot', lastName: process.env.APP_USER_LASTNAME || 'Admin', workspace: 'spot' }
    persistSession(t, sessions[t])
    res.setHeader('Set-Cookie', 'spot_session=' + t + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + (60*60*24*7))
    return res.redirect('/')
  }
  res.redirect('/login?err=1')
})
app.post('/logout', (req, res) => { const _t = getToken(req); delete sessions[_t]; dropSession(_t); res.setHeader('Set-Cookie', 'spot_session=; Path=/; Max-Age=0'); res.json({ ok: true }) })
app.get('/api/me', auth, (req, res) => { const s = sessions[getToken(req)] || {}; const firstName = s.firstName || 'Spot'; const lastName = s.lastName || (s.firstName ? '' : 'Admin'); const role = s.role || 'admin'; const initials = (firstName[0]||'') + (lastName[0]||''); res.json({ firstName, lastName, role, workspace: s.workspace || 'spot', viewingAs: s.realWorkspace ? s.workspace : null, initials: initials.toUpperCase() }) })
async function ensureChannelsTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS user_channels (username TEXT, platform TEXT, handle TEXT, PRIMARY KEY (username, platform))") }
app.get('/api/channels', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureChannelsTable()
    const r = await getAuthPool().query('SELECT platform, handle FROM user_channels WHERE username=$1', [s.u])
    res.json({ channels: r.rows })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/channels/add', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { platform, handle } = req.body || {}
    if (!platform || !handle) return res.status(400).json({ error: 'platform och handle krävs' })
    await ensureChannelsTable()
    await getAuthPool().query('INSERT INTO user_channels (username,platform,handle) VALUES ($1,$2,$3) ON CONFLICT (username,platform) DO UPDATE SET handle=$3', [s.u, platform, handle])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/channels/remove', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { platform } = req.body || {}
    await ensureChannelsTable()
    await getAuthPool().query('DELETE FROM user_channels WHERE username=$1 AND platform=$2', [s.u, platform])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/team/invite', auth, async (req, res) => {
  const s = sessions[getToken(req)] || {}
  if ((s.role || 'admin') !== 'admin') return res.status(403).json({ error: 'Endast admin kan bjuda in medlemmar' })
  try {
    const { name, email, password, role, username: wantedUsername } = req.body || {}
    if (!name || !email || !password) return res.status(400).json({ error: 'Namn, e-post och lösenord krävs' })
    if (passwordError(password)) return res.status(400).json({ error: passwordError(password) })
    const roleMap = { admin: 'admin', editor: 'redaktor', viewer: 'granskare' }
    const dbRole = roleMap[role] || 'granskare'
    const parts = String(name).trim().split(/\s+/)
    const firstName = parts[0] || name
    const lastName = parts.slice(1).join(' ') || ''
    let username = slugBase(wantedUsername || String(email).split('@')[0]).replace(/[^\p{L}\p{N}]/gu, '')
    if (!username) username = slugBase(String(email).split('@')[0]).replace(/[^\p{L}\p{N}]/gu, '')
    if (wantedUsername) {
      const taken = await getAuthPool().query('SELECT 1 FROM app_users WHERE username=$1', [username])
      if (taken.rows.length) return res.status(400).json({ error: 'Användarnamnet är upptaget' })
    }
    await ensureUsersTable()
    let candidate = username, n = 1
    while ((await getAuthPool().query('SELECT 1 FROM app_users WHERE username=$1', [candidate])).rows.length) {
      candidate = username + n; n++
    }
    username = candidate
    await getAuthPool().query('INSERT INTO app_users (username,password,role,first_name,last_name,email,workspace) VALUES ($1,$2,$3,$4,$5,$6,$7)', [username, hashPassword(password), dbRole, firstName, lastName, email, s.workspace || 'spot'])
    logBillingEvent(s.workspace || 'spot', 'member_added', { username, name: (firstName + ' ' + lastName).trim(), role: dbRole, addedBy: s.u })
    const loginLink = 'https://' + req.get('host') + '/login'
    const mailSent = await sendAppMail({
      to: email,
      subject: 'Du har bjudits in till spot. Brand Studio',
      text: 'Hej ' + firstName + '!\n\nDu har lagts till i spot. Brand Studio.\n\nAnvandarnamn: ' + username + '\nLosenord: ' + password + '\n\nLogga in har: ' + loginLink + '\n\nVi rekommenderar att du byter losenord efter forsta inloggningen.',
      html: '<p>Hej ' + firstName + '!</p><p>Du har lagts till i <strong>spot. Brand Studio</strong>.</p><p>Användarnamn: <strong>' + username + '</strong><br>Lösenord: <strong>' + password + '</strong></p><p><a href="' + loginLink + '">Logga in här</a></p><p>Vi rekommenderar att du byter lösenord efter första inloggningen.</p>'
    })
    res.json({ ok: true, username, mailSent })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/team/role', auth, async (req, res) => {
  const s = sessions[getToken(req)] || {}
  if ((s.role || 'admin') !== 'admin') return res.status(403).json({ error: 'Endast admin kan ändra roller' })
  try {
    const { username, role } = req.body || {}
    const roleMap = { admin: 'admin', editor: 'redaktor', viewer: 'granskare' }
    const dbRole = roleMap[role] || 'granskare'
    await ensureUsersTable()
    await getAuthPool().query('UPDATE app_users SET role=$1 WHERE username=$2', [dbRole, username])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.get('/api/team/members', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureUsersTable()
    const r = await getAuthPool().query('SELECT username, role, first_name, last_name, email FROM app_users WHERE workspace=$1 ORDER BY username', [s.workspace || 'spot'])
    res.json({ members: r.rows })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/team/remove', auth, async (req, res) => {
  const s = sessions[getToken(req)] || {}
  if ((s.role || 'admin') !== 'admin') return res.status(403).json({ error: 'Endast admin kan ta bort medlemmar' })
  try {
    const { username } = req.body || {}
    if (!username) return res.status(400).json({ error: 'username saknas' })
    await ensureUsersTable()
    if (username === s.u) return res.status(400).json({ error: 'Du kan inte ta bort dig själv' })
    const del = await getAuthPool().query('DELETE FROM app_users WHERE username=$1 AND workspace=$2', [username, s.workspace || 'spot'])
    if (!del.rowCount) return res.status(404).json({ error: 'Medlemmen hittades inte i ert team' })
    // Logga ut den borttagna medlemmen direkt
    Object.keys(sessions).forEach(function(t){ if (sessions[t] && sessions[t].u === username) { delete sessions[t]; dropSession(t) } })
    logBillingEvent(s.workspace || 'spot', 'member_removed', { username, removedBy: s.u })
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/change-password', auth, async (req, res) => { const { currentPassword, newPassword } = req.body || {}; if (passwordError(newPassword)) return res.status(400).json({ error: passwordError(newPassword) }); if (!verifyPassword(currentPassword, await getPassword())) return res.status(401).json({ error: 'Fel nuvarande lösenord' }); await setPassword(String(newPassword)); res.json({ ok: true }) })
app.get('/forgot', (_req, res) => res.send(FORGOT_HTML))
app.post('/forgot', async (req, res) => {
  try {
    if (!process.env.RESEND_API_KEY) return res.redirect('/forgot?err=nomailer')
    const submitted = String((req.body || {}).email || '').trim().toLowerCase()
    if (!submitted) return res.redirect('/forgot?err=nomatch')
    const recoveryEmail = process.env.APP_RECOVERY_EMAIL
    let targetUsername = null
    let targetEmail = null
    if (recoveryEmail && submitted === recoveryEmail.trim().toLowerCase()) {
      targetUsername = null
      targetEmail = recoveryEmail
    } else {
      await ensureUsersTable()
      const r = await getAuthPool().query('SELECT username, email FROM app_users WHERE lower(email)=$1', [submitted])
      if (!r.rows.length) return res.redirect('/forgot?err=nomatch')
      targetUsername = r.rows[0].username
      targetEmail = r.rows[0].email
    }
    const t = makeResetToken(targetUsername)
    const link = 'https://' + req.get('host') + '/reset?token=' + t
    const ok = await sendAppMail({
      to: targetEmail,
      subject: 'spot. – Återställ lösenord',
      text: 'Någon har begärt att återställa lösenordet för spot. Brand Studio.\n\nKlicka på länken nedan för att välja ett nytt lösenord (giltig i 30 minuter):\n' + link + '\n\nOm det inte var du kan du ignorera detta mail.',
      html: '<p>Någon har begärt att återställa lösenordet för <strong>spot. Brand Studio</strong>.</p><p><a href="' + link + '">Klicka här för att välja ett nytt lösenord</a> (giltig i 30 minuter).</p><p>Om det inte var du kan du ignorera detta mail.</p>'
    })
    if (!ok) return res.redirect('/forgot?err=1')
    res.redirect('/forgot?sent=1')
  } catch (e) { console.error('[forgot] error:', e.message); res.redirect('/forgot?err=1') }
})
app.get('/reset', (req, res) => { const t = req.query.token || ''; if (!validResetToken(t)) return res.send(RESET_INVALID_HTML); res.send(RESET_HTML.split('__TOKEN__').join(t)) })
app.post('/reset', async (req, res) => { const { token, newPassword } = req.body || {}; if (!validResetToken(token)) return res.redirect('/forgot?err=1'); if (passwordError(newPassword)) return res.redirect('/reset?token=' + token + '&err=1'); const rt = resetTokens[token]; if (rt && rt.username) { await getAuthPool().query('UPDATE app_users SET password=$1 WHERE username=$2', [hashPassword(newPassword), rt.username]) } else { await setPassword(String(newPassword)) } delete resetTokens[token]; res.redirect('/login?reset=1') })
app.get('/inject.js', (_req, res) => { try { res.setHeader('Content-Type', 'application/javascript'); res.send(fs.readFileSync(path.join(__dirname, 'inject.js'), 'utf-8')) } catch (e) { res.send('// inject.js not found') } })
app.get('/', auth, (req, res) => { try { const html = fs.readFileSync(path.join(__dirname, 'poc.html'), 'utf-8'); const tag = '<script src="/inject.js"></script>'; const idx = html.lastIndexOf('</script>'); const patched = html.slice(0, idx + 9) + tag + html.slice(idx + 9); res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.send(patched) } catch (e) { res.status(500).send('Error: ' + e.message) } })
// Text från Gemini: bildmodellen (Nano Banana 2.1) svarar ibland utan text, så textjobb provar en textmodell först.
// Ordning: GEMINI_TEXT_MODEL (om satt) → gemini-3.8-flash → gemini-nano-banana-2.1. Tar första modellen som faktiskt ger text.
async function geminiText(apiKey, parts, gen) {
  const models = [process.env.GEMINI_TEXT_MODEL, 'gemini-3.8-flash', 'gemini-nano-banana-2.1'].filter(Boolean)
  const notes = []
  for (const model of models) {
    try {
      const cfg = Object.assign({}, gen || {})
      if (model.indexOf('banana') >= 0 || model.indexOf('image') >= 0) cfg.responseModalities = ['TEXT']
      const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + apiKey, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ parts }], generationConfig: cfg }) })
      const d = await r.json()
      if (d.error) { notes.push(model + ': ' + d.error.message); continue }
      const c = d.candidates?.[0] || {}
      const text = (c.content?.parts || []).filter(p => p.text && !p.thought).map(p => p.text).join('').trim()
      if (text) return { text, model }
      notes.push(model + ': tomt svar (' + (c.finishReason || d.promptFeedback?.blockReason || 'okänd orsak') + ')')
    } catch (e) { notes.push(model + ': ' + e.message) }
  }
  throw new Error('Gemini gav ingen text – ' + notes.join(' | '))
}
app.post('/api/generate', auth, async (req, res) => { try { const { channels = ['instagram'], brief = '', brand = null } = req.body; const nProps = Math.min(6, Math.max(1, parseInt(req.body.count, 10) || 3)); const apiKey = process.env.GEMINI_API_KEY; if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY saknas' }); const chList = Array.isArray(channels) ? channels : [channels]; let brandBlock = ''; if (brand) { brandBlock = ' Varumarkesprofil - foljs strikt: Tonalitet: ' + (brand.tone||'') + '. Visuell stil: ' + (brand.visualStyle||'') + '. Tjanster: ' + (brand.services||'') + '.'; if (brand.dos && brand.dos.length) brandBlock += ' Gor: ' + brand.dos.join('; ') + '.'; if (brand.donts && brand.donts.length) brandBlock += ' Undvik: ' + brand.donts.join('; ') + '.'; if (brand.forbidden) brandBlock += ' Forbjudna ord/fraser: ' + brand.forbidden + '.'; } const brandName = (brand && brand.name) ? (brand.name + (brand.location ? (', ' + brand.location) : '')) : 'spot. creative studio Halmstad'; const prompt = 'Du ar copywriter for ' + brandName + '.' + brandBlock + ' Brief: ' + (brief || ('Generellt om ' + brandName)) + '. Kanaler: ' + chList.join(', ') + '. Generera EXAKT ' + nProps + ' korta forslag max 100 ord. "title" ar rubriken som star pa bilden: en passande rubrik som sammanfattar just det forslagets "content" (innehallstexten), max 5 ord, slagkraftig, olika i varje forslag. Den far INTE vara uppdraget/prompten eller en omskrivning av den. Svara ENDAST med JSON-array: [{"title":"...","content":"...","hashtags":["..."],"cta":"..."},{"title":"...","content":"...","hashtags":["..."],"cta":"..."},{"title":"...","content":"...","hashtags":["..."],"cta":"..."}]'; const _gt = await geminiText(apiKey, [{ text: prompt }], { temperature: 0.9, maxOutputTokens: 8192 }); let s = _gt.text.replace(/```json/g, '').replace(/```/g, '').trim(); s = s.replace(/,(\s*[}\]])/g, '$1'); const start = s.indexOf('['), end = s.lastIndexOf(']'); if (start < 0 || end < 0) throw new Error('Ingen array i svar'); const flat = JSON.parse(s.slice(start, end + 1));
flat.forEach(function(p){ if (p && typeof p === 'object') { if (typeof p.title === 'string') p.title = capitalizeAfterSentences(p.title); if (typeof p.content === 'string') p.content = capitalizeAfterSentences(p.content); } }); const proposals = {}; chList.forEach(ch => { proposals[ch] = flat }); res.json({ proposals }) } catch (e) { res.status(500).json({ error: e.message }) } })
// Tvättar en kunds mallbild: AI tar bort all text och alla loggor men behåller designen,
// så att inläggets egen rubrik och text kan läggas ovanpå. Resultatet sparas i stored_images.
// Samma mall tvättas bara en gång: färdig tvätt hämtas från varumärket, pågående tvätt delas mellan flikar
const _cleanInflight = {}
app.post('/api/clean-template', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const ws = s.workspace || 'spot'
    const apiKey = process.env.GEMINI_API_KEY
    if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY saknas' })
    let src = String((req.body || {}).src || '')
    const _ck = ws + '|' + src
    try {
      await ensureBrandTable()
      const _br0 = await getAuthPool().query('SELECT data FROM workspace_brand WHERE workspace=$1', [ws])
      const _t0 = (((_br0.rows[0] && _br0.rows[0].data) || {}).templates || []).find(t => t && t.src === src && t.cleanSrc && t.cleanFor === src)
      if (_t0) return res.json({ url: _t0.cleanSrc, cached: true })
    } catch (e0) {}
    if (_cleanInflight[_ck]) { try { return res.json({ url: await _cleanInflight[_ck], shared: true }) } catch (e1) { return res.status(502).json({ error: e1.message }) } }
    let _done = null
    _cleanInflight[_ck] = new Promise((ok, no) => { _done = { ok, no } }); _cleanInflight[_ck].catch(() => {})
    const _json = res.json.bind(res)
    res.json = function (b) { try { if (b && b.url) _done.ok(b.url); else _done.no(new Error((b && b.error) || 'Tvätten misslyckades')) } catch (e2) {} delete _cleanInflight[_ck]; return _json(b) }
    let mime = null, b64 = null
    const dm = src.match(/^data:(image\/(png|jpeg|jpg|webp|gif));base64,(.+)$/)
    const im = src.match(/\/img\/([a-f0-9]{24})$/)
    if (dm) { mime = dm[1]; b64 = dm[3] }
    else if (im) {
      await ensureImagesTable()
      const r0 = await getAuthPool().query('SELECT mime, data, workspace FROM stored_images WHERE id=$1', [im[1]])
      if (!r0.rows.length || r0.rows[0].workspace !== ws) return res.status(404).json({ error: 'Mallen hittades inte' })
      mime = r0.rows[0].mime; b64 = r0.rows[0].data.toString('base64')
    } else if (/^\/assets\/tpl-[a-z-]+\.png$/.test(src) && _TPL[src.slice(8)]) {
      // Spots inbyggda mallbilder
      mime = 'image/png'; b64 = fs.readFileSync(path.join(__dirname, 'assets', _TPL[src.slice(8)])).toString('base64')
    } else return res.status(400).json({ error: 'Ogiltig mall' })
    if (b64.length > 11 * 1024 * 1024) return res.status(400).json({ error: 'Mallen är för stor' })
    const prompt = 'Edit this social media template image. Remove ALL text: every headline, word, letter, number, caption, hashtag, handle, logo and wordmark. Keep everything else exactly as it is: layout, colors, shapes, frames, photos and background. Fill the areas where text was removed seamlessly with the surrounding background so they look empty and ready for new text. Keep the same aspect ratio.'
    const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-nano-banana-2.1:generateContent?key=' + apiKey, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ parts: [{ inlineData: { mimeType: mime, data: b64 } }, { text: prompt }] }], generationConfig: { responseModalities: ['IMAGE'] } }) })
    const data = await r.json()
    if (data.error) throw new Error('Gemini: ' + data.error.message)
    const part = (data.candidates?.[0]?.content?.parts || []).find(p => p.inlineData?.mimeType?.startsWith('image/'))
    if (!part) return res.status(502).json({ error: 'Ingen bild från AI' })
    const url = await storeDataUrlImage('data:' + part.inlineData.mimeType + ';base64,' + part.inlineData.data, ws, s.u, '')
    if (!url) return res.status(500).json({ error: 'Kunde inte spara mallen' })
    // Spara den tvättade mallen i varumärket direkt, så att den inte behöver tvättas igen (oavsett roll)
    try {
      await ensureBrandTable()
      const br = await getAuthPool().query('SELECT data FROM workspace_brand WHERE workspace=$1', [ws])
      const bd = (br.rows[0] && br.rows[0].data) || null
      if (bd && Array.isArray(bd.templates)) {
        let hit = false
        bd.templates.forEach(t => { if (t && t.src === src) { t.cleanSrc = url; t.cleanFor = src; hit = true } })
        if (hit) await getAuthPool().query('UPDATE workspace_brand SET data=$2 WHERE workspace=$1', [ws, JSON.stringify(bd)])
      }
    } catch (e2) {}
    res.json({ url })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
// Gör en platt mallbild redigerbar: AI hittar varje textrad och loggan (position, färg, roll).
// Klienten lyfter sedan ut dem ur bilden och gör dem till egna element i editorn.
app.post('/api/template-layers', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const ws = s.workspace || 'spot'
    const apiKey = process.env.GEMINI_API_KEY
    if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY saknas' })
    const src = String((req.body || {}).src || '')
    let mime = null, b64 = null
    const dm = src.match(/^data:(image\/(png|jpeg|jpg|webp|gif));base64,(.+)$/)
    const im = src.match(/\/img\/([a-f0-9]{24})$/)
    if (dm) { mime = dm[1]; b64 = dm[3] }
    else if (im) {
      await ensureImagesTable()
      const r0 = await getAuthPool().query('SELECT mime, data, workspace FROM stored_images WHERE id=$1', [im[1]])
      if (!r0.rows.length || r0.rows[0].workspace !== ws) return res.status(404).json({ error: 'Mallen hittades inte' })
      mime = r0.rows[0].mime; b64 = r0.rows[0].data.toString('base64')
    } else if (/^\/assets\/tpl-[a-z-]+\.png$/.test(src) && _TPL[src.slice(8)]) {
      mime = 'image/png'; b64 = fs.readFileSync(path.join(__dirname, 'assets', _TPL[src.slice(8)])).toString('base64')
    } else return res.status(400).json({ error: 'Ogiltig mall' })
    const prompt = 'You analyse a social media post template image. Find EVERY piece of visible text (one entry per text line), the brand logo (if any) and every photo. ' +
      'Return JSON: {"elements":[{"kind":"text","text":"exact text as written","box_2d":[ymin,xmin,ymax,xmax],"color":"#rrggbb","role":"headline|subheadline|body|caption|label","bold":true|false,"italic":false,"align":"left|center|right","rotation":0|90|-90},{"kind":"logo","box_2d":[ymin,xmin,ymax,xmax]},{"kind":"photo","box_2d":[ymin,xmin,ymax,xmax]}]}. ' +
      'photo = every separate photograph or picture area (for example each image in a collage, or a placeholder area marked for an image); give one entry per photo with a tight box around that photo only. ' +
      'box_2d uses coordinates normalised to 0-1000 and must tightly enclose the text line or logo (include the whole logo, also its background plate if it sits on one). ' +
      'rotation: 0 for normal horizontal text, -90 if the text runs vertically from bottom to top, 90 if it runs from top to bottom. ' +
      'role: headline = the largest text, subheadline = medium accent text, body = normal sentences, caption = small text, label = tiny tags like "[ DIN BILD HÄR ]". Do not include decorative shapes. Only JSON.'
    const txt = (await geminiText(apiKey, [{ text: prompt }, { inlineData: { mimeType: mime, data: b64 } }], { temperature: 0 })).text
    // Tolerant tolkning: modellen kan svara med {elements:[…]}, en ren lista, i kodblock eller med andra namn på rutan
    const clean = txt.replace(/```json/gi, '').replace(/```/g, '').trim()
    let out = null
    try { out = JSON.parse(clean) } catch (e) {
      const mo = clean.match(/\{[\s\S]*\}/), ma = clean.match(/\[[\s\S]*\]/)
      try { out = mo ? JSON.parse(mo[0]) : null } catch (e2) { out = null }
      if (!out && ma) { try { out = JSON.parse(ma[0]) } catch (e3) { out = null } }
    }
    const list = Array.isArray(out) ? out : ((out && (out.elements || out.items || out.texts)) || [])
    const els = list.map(e => { if (!e) return null; const b = e.box_2d || e.box2d || e.bbox || e.box; return Array.isArray(b) && b.length === 4 ? Object.assign({}, e, { box_2d: b.map(Number) }) : null }).filter(Boolean)
    res.json(els.length ? { elements: els } : { elements: [], raw: clean.slice(0, 1500) })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/generate-image', auth, async (req, res) => { try { const { brief = '', style = 'modern', brand = null, previousImageBase64 = null, previousImageMimeType = 'image/png', includeBrand = true } = req.body; const apiKey = process.env.GEMINI_API_KEY; if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY saknas' }); let brandVisual = ''; if (brand && includeBrand) { brandVisual = ' Varumarkets visuella stil (foljs strikt): ' + (brand.visualStyle||'') + '. Fargpalett: ' + (brand.colors||'') + '.'; } const brandNameImg = includeBrand ? ((brand && brand.name) ? brand.name : 'spot. creative studio Halmstad') : ''; let promptText = 'CRITICAL RULE: absolutely NO text, no letters, no words, no numbers, no captions, no logos, no wordmarks, no watermarks, no icons and no brand marks anywhere in the image - it must be a purely visual photo with zero written characters and zero logos or brand symbols. Professional social media image.' + brandVisual + ' Style: ' + style + '. Brief: ' + (brief || 'creative studio') + '.'; const imgParts = []; if (previousImageBase64) { imgParts.push({ inlineData: { mimeType: previousImageMimeType || 'image/png', data: previousImageBase64 } }); promptText = 'Skapa en variant av den har bilden utifran: ' + promptText; /* Ingen uppmaning om att ta bort vattenstämplar/loggor ur referensbilden: Google tolkar det som borttagning av upphovsmärkning och stoppar bilden (IMAGE_SAFETY). Regeln ovan om inga loggor räcker. */ } imgParts.push({ text: promptText }); const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-nano-banana-2.1:generateContent?key=' + apiKey, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ parts: imgParts }], generationConfig: { responseModalities: ['IMAGE'] } }) }); let data = await r.json(); if (data.error) throw new Error('Gemini: ' + data.error.message); /* Riktiga foton (t.ex. konstverk eller människor) får bildmodellen ofta inte ändra direkt (IMAGE_SAFETY). Då beskrivs bilden först i text och återskapas utifrån beskrivningen, så att man ändå utgår från samma bild. */ if (previousImageBase64 && !(data.candidates?.[0]?.content?.parts || []).some(p => p.inlineData)) { const _fbNotes = []; const _asks = ['Describe this photo so an image generator can recreate a very similar photo: subject, setting, composition, camera angle, framing, light, colours and mood. Use only generic words: never name artists, artworks, brands, logos, places or people, and do not mention any text or letters in the image. Describe people only by pose and clothing. Max 90 words, only the description.', 'Describe only the overall scene of this photo in 2-3 short generic sentences (type of place, layout, colours, light, mood). Replace every artwork, poster or person with a simple generic shape or silhouette. No names, no text, no letters.']; for (const _ask of _asks) { try { const desc = (await geminiText(apiKey, [{ inlineData: { mimeType: previousImageMimeType || 'image/png', data: previousImageBase64 } }, { text: _ask }])).text.replace(/["“”]/g, ''); const r2 = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-nano-banana-2.1:generateContent?key=' + apiKey, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ parts: [{ text: promptText.replace('Skapa en variant av den har bilden utifran: ', '') + ' Recreate this scene as closely as possible (same composition, framing, light and colours), as an original photo, with the requested changes: ' + desc }] }], generationConfig: { responseModalities: ['IMAGE'] } }) }); const d2 = await r2.json(); if (!d2.error && (d2.candidates?.[0]?.content?.parts || []).some(p => p.inlineData)) { data = d2; break } _fbNotes.push((d2.error ? d2.error.message : (d2.candidates?.[0]?.finishReason || d2.promptFeedback?.blockReason || 'ingen bild')) + ' <- ' + desc.slice(0, 400)) } catch (e3) { _fbNotes.push(e3.message) } } if (_fbNotes.length) console.log('generate-image fallback:', _fbNotes.join(' | ')) } const imgPart = (data.candidates?.[0]?.content?.parts || []).find(p => p.inlineData?.mimeType?.startsWith('image/')); if (imgPart) return res.json({ imageUrl: 'data:' + imgPart.inlineData.mimeType + ';base64,' + imgPart.inlineData.data }); const _why = (data.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join(' ').trim().slice(0, 160) || data.candidates?.[0]?.finishReason || data.promptFeedback?.blockReason || ''; res.status(502).json({ error: 'AI:n skickade ingen bild' + (_why ? ' (' + _why + ')' : '') + ' – försök igen eller ändra beskrivningen' }) } catch (e) { res.status(500).json({ error: e.message }) } })
// ── Utkast från editorn: delas av alla i arbetsytan, bara admin kan radera ──
async function ensureDrafts() { await getAuthPool().query('CREATE TABLE IF NOT EXISTS edit_drafts (workspace TEXT, key TEXT, data JSONB, saved BOOLEAN DEFAULT FALSE, updated_by TEXT, updated_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY (workspace, key))') }
function draftKey(s, k) { k = String(k || '').slice(0, 120); return k === 'create' ? 'create:' + (s.u || '') : k }
app.get('/api/edit-draft', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureDrafts()
    const r = await getAuthPool().query('SELECT data, saved, updated_by, updated_at FROM edit_drafts WHERE workspace=$1 AND key=$2', [s.workspace || 'spot', draftKey(s, req.query.key)])
    if (!r.rows.length || r.rows[0].saved) return res.json({})
    res.json({ post: r.rows[0].data, by: r.rows[0].updated_by || '', ts: new Date(r.rows[0].updated_at).getTime() })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/edit-draft', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}, ws = s.workspace || 'spot'
    const { key, post, saved } = req.body || {}
    if (!key) return res.status(400).json({ error: 'Nyckel saknas' })
    await ensureDrafts()
    const k = draftKey(s, key), by = [s.firstName, s.lastName].filter(Boolean).join(' ') || s.u || ''
    // Inlägget sparades på riktigt: utkastet markeras som klart (raderas inte – det får bara admin göra)
    if (saved) { await getAuthPool().query('UPDATE edit_drafts SET saved=TRUE, updated_by=$3, updated_at=NOW() WHERE workspace=$1 AND key=$2', [ws, k, by]); return res.json({ ok: true }) }
    if (!post || typeof post !== 'object') return res.status(400).json({ error: 'Utkast saknas' })
    await getAuthPool().query('INSERT INTO edit_drafts (workspace, key, data, saved, updated_by, updated_at) VALUES ($1,$2,$3,FALSE,$4,NOW()) ON CONFLICT (workspace, key) DO UPDATE SET data=$3, saved=FALSE, updated_by=$4, updated_at=NOW()', [ws, k, JSON.stringify(post), by])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.delete('/api/edit-draft', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.role || 'admin') !== 'admin') return res.status(403).json({ error: 'Endast admin kan radera utkast' })
    await ensureDrafts()
    await getAuthPool().query('DELETE FROM edit_drafts WHERE workspace=$1 AND key=$2', [s.workspace || 'spot', draftKey(s, req.query.key)])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/save-post', auth, async (req, res) => { try { const s = sessions[getToken(req)] || {}; const { Pool } = require('pg'); const pool = getAuthPool(); await pool.query('CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, data JSONB, created_at TIMESTAMPTZ DEFAULT NOW())'); const post = req.body; post.workspace = s.workspace || 'spot'; for (const _k of ['imageUrl', 'aiImageUrl']) { if (typeof post[_k] === 'string' && post[_k].indexOf('data:') === 0) { const _u = await storeDataUrlImage(post[_k], post.workspace, s.u, 'https://' + req.get('host')); if (_u) post[_k] = _u } } const _pid = post.id || Date.now().toString(); const _links = postLinks(_pid, post, 'https://' + req.get('host')); await ensurePostLinkColumns(); await pool.query('INSERT INTO posts (id,data,link,image_url) VALUES ($1,$2,$3,$4) ON CONFLICT (id) DO UPDATE SET data=$2,link=$3,image_url=$4,created_at=NOW()', [_pid, JSON.stringify(post), _links.link, _links.image_url]); res.json({ saved: true }) } catch (e) { res.status(500).json({ error: e.message }) } })
app.get('/api/published-posts', auth, async (req, res) => { try { const s = sessions[getToken(req)] || {}; const { Pool } = require('pg'); const pool = getAuthPool(); await pool.query('CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, data JSONB, created_at TIMESTAMPTZ DEFAULT NOW())'); const result = await pool.query("SELECT data FROM posts WHERE data->>'status' IN ('published','archived') AND data->>'workspace' = $1 AND (data->>'deleted' IS NULL OR data->>'deleted' <> 'true') ORDER BY created_at DESC LIMIT 200", [s.workspace || 'spot']); res.json({ posts: result.rows.map(r => r.data) }) } catch (e) { res.status(500).json({ error: e.message }) } })
app.get('/api/all-posts', auth, async (req, res) => { try { const s = sessions[getToken(req)] || {}; const { Pool } = require('pg'); const pool = getAuthPool(); await pool.query('CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, data JSONB, created_at TIMESTAMPTZ DEFAULT NOW())'); const result = await pool.query("SELECT data FROM posts WHERE data->>'workspace' = $1 AND (data->>'deleted' IS NULL OR data->>'deleted' <> 'true') ORDER BY created_at DESC LIMIT 500", [s.workspace || 'spot']); res.json({ posts: result.rows.map(r => r.data) }) } catch (e) { res.status(500).json({ error: e.message }) } })
async function ensureLinkedInTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS linkedin_accounts (username TEXT PRIMARY KEY, access_token TEXT, expires_at BIGINT, li_sub TEXT, li_name TEXT)") }
app.get('/auth/linkedin', auth, (req, res) => {
  const s = sessions[getToken(req)] || {}
  const state = makeToken()
  s.liState = state
  const redirectUri = req.protocol + '://' + req.get('host') + '/auth/linkedin/callback'
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.LINKEDIN_CLIENT_ID || '',
    redirect_uri: redirectUri,
    state,
    scope: 'openid profile email w_member_social'
  })
  res.redirect('https://www.linkedin.com/oauth/v2/authorization?' + params.toString())
})
app.get('/auth/linkedin/callback', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { code, state } = req.query
    if (!code || state !== s.liState) return res.send('<p>Ogiltig eller utgången LinkedIn-inloggning. <a href="/">Tillbaka</a></p>')
    const redirectUri = req.protocol + '://' + req.get('host') + '/auth/linkedin/callback'
    const tokenRes = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: process.env.LINKEDIN_CLIENT_ID || '',
        client_secret: process.env.LINKEDIN_CLIENT_SECRET || ''
      })
    })
    const tokenData = await tokenRes.json()
    if (!tokenData.access_token) return res.send('<p>Kunde inte logga in med LinkedIn: ' + (tokenData.error_description || tokenData.error || 'okänt fel') + '. <a href="/">Tillbaka</a></p>')
    const meRes = await fetch('https://api.linkedin.com/v2/userinfo', { headers: { Authorization: 'Bearer ' + tokenData.access_token } })
    const me = await meRes.json()
    await ensureLinkedInTable()
    const expiresAt = Date.now() + (tokenData.expires_in || 5000) * 1000
    await getAuthPool().query(
      'INSERT INTO linkedin_accounts (username,access_token,expires_at,li_sub,li_name) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (username) DO UPDATE SET access_token=$2, expires_at=$3, li_sub=$4, li_name=$5',
      [s.u, tokenData.access_token, expiresAt, me.sub, me.name || '']
    )
    res.redirect('/?linkedin=connected')
  } catch (e) {
    res.send('<p>Fel vid LinkedIn-inloggning: ' + e.message + '. <a href="/">Tillbaka</a></p>')
  }
})
app.get('/api/linkedin/status', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureLinkedInTable()
    const r = await getAuthPool().query('SELECT li_name, expires_at FROM linkedin_accounts WHERE username=$1', [s.u])
    if (!r.rows.length) return res.json({ connected: false })
    res.json({ connected: true, name: r.rows[0].li_name })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/linkedin/disconnect', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureLinkedInTable()
    await getAuthPool().query('DELETE FROM linkedin_accounts WHERE username=$1', [s.u])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/linkedin/publish', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    let { text, imageDataUrl } = req.body || {}
    if (!text) return res.status(400).json({ error: 'Text saknas' })
    const _im = imageDataUrl && String(imageDataUrl).match(/\/img\/([a-f0-9]{24})$/)
    if (_im) {
      await ensureImagesTable()
      const _ir = await getAuthPool().query('SELECT mime, data, workspace FROM stored_images WHERE id=$1', [_im[1]])
      imageDataUrl = (_ir.rows.length && _ir.rows[0].workspace === (s.workspace || 'spot')) ? ('data:' + _ir.rows[0].mime + ';base64,' + _ir.rows[0].data.toString('base64')) : null
    }
    await ensureLinkedInTable()
    const r = await getAuthPool().query('SELECT access_token, li_sub FROM linkedin_accounts WHERE username=$1', [s.u])
    if (!r.rows.length) return res.status(400).json({ error: 'LinkedIn är inte anslutet. Anslut kontot först.' })
    const { access_token, li_sub } = r.rows[0]
    const author = 'urn:li:person:' + li_sub
    let mediaAsset = null
    if (imageDataUrl && imageDataUrl.indexOf('data:') === 0) {
      const regRes = await fetch('https://api.linkedin.com/v2/assets?action=registerUpload', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + access_token, 'Content-Type': 'application/json' },
        body: JSON.stringify({ registerUploadRequest: { recipes: ['urn:li:digitalmediaRecipe:feedshare-image'], owner: author, serviceRelationships: [{ relationshipType: 'OWNER', identifier: 'urn:li:userGeneratedContent' }] } })
      })
      const regData = await regRes.json()
      const uploadUrl = regData.value.uploadMechanism['com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest'].uploadUrl
      mediaAsset = regData.value.asset
      const base64 = imageDataUrl.split(',')[1]
      const buffer = Buffer.from(base64, 'base64')
      await fetch(uploadUrl, { method: 'PUT', headers: { Authorization: 'Bearer ' + access_token }, body: buffer })
    }
    const postBody = {
      author,
      lifecycleState: 'PUBLISHED',
      specificContent: {
        'com.linkedin.ugc.ShareContent': {
          shareCommentary: { text },
          shareMediaCategory: mediaAsset ? 'IMAGE' : 'NONE',
          media: mediaAsset ? [{ status: 'READY', media: mediaAsset }] : undefined
        }
      },
      visibility: { 'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC' }
    }
    const postRes = await fetch('https://api.linkedin.com/v2/ugcPosts', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + access_token, 'Content-Type': 'application/json', 'X-Restli-Protocol-Version': '2.0.0' },
      body: JSON.stringify(postBody)
    })
    if (!postRes.ok) { const errText = await postRes.text(); return res.status(500).json({ error: 'LinkedIn avvisade inlägget: ' + errText }) }
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
// --- LinkedIn Company Page (official Community Management API) ---
async function ensureLinkedInCompanyTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS linkedin_company_accounts (username TEXT PRIMARY KEY, access_token TEXT, expires_at BIGINT, org_urn TEXT, org_name TEXT)") }
app.get('/auth/linkedin/company', auth, (req, res) => {
  const s = sessions[getToken(req)] || {}
  const state = makeToken()
  s.liCompanyState = state
  const redirectUri = req.protocol + '://' + req.get('host') + '/auth/linkedin/company/callback'
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.LINKEDIN_COMPANY_CLIENT_ID || '',
    redirect_uri: redirectUri,
    state,
    scope: 'rw_organization_admin w_organization_social r_organization_social'
  })
  res.redirect('https://www.linkedin.com/oauth/v2/authorization?' + params.toString())
})
app.get('/auth/linkedin/company/callback', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { code, state } = req.query
    if (!code || state !== s.liCompanyState) return res.send('<p>Ogiltig eller utgången LinkedIn-inloggning (företag). <a href="/">Tillbaka</a></p>')
    const redirectUri = req.protocol + '://' + req.get('host') + '/auth/linkedin/company/callback'
    const tokenRes = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: process.env.LINKEDIN_COMPANY_CLIENT_ID || '',
        client_secret: process.env.LINKEDIN_COMPANY_CLIENT_SECRET || ''
      })
    })
    const tokenData = await tokenRes.json()
    if (!tokenData.access_token) return res.send('<p>Kunde inte ansluta LinkedIn-företagssida: ' + (tokenData.error_description || tokenData.error || 'okänt fel') + '. <a href="/">Tillbaka</a></p>')
    const aclRes = await fetch('https://api.linkedin.com/v2/organizationAcls?q=roleAssignee&role=ADMINISTRATOR&projection=(elements*(organization~(localizedName),organizationalTarget~(localizedName)))', {
      headers: { Authorization: 'Bearer ' + tokenData.access_token }
    })
    const aclData = await aclRes.json()
    const first = (aclData.elements || [])[0] || {}
    const orgTargetUrn = first.organizationalTarget || first.organization || null
    const orgInfo = first['organizationalTarget~'] || first['organization~'] || {}
    if (!orgTargetUrn) return res.send('<p>Inget LinkedIn-företag hittades där du är administratör. <a href="/">Tillbaka</a></p>')
    await ensureLinkedInCompanyTable()
    const expiresAt = Date.now() + (tokenData.expires_in || 5000) * 1000
    await getAuthPool().query(
      'INSERT INTO linkedin_company_accounts (username,access_token,expires_at,org_urn,org_name) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (username) DO UPDATE SET access_token=$2, expires_at=$3, org_urn=$4, org_name=$5',
      ['ws:' + (s.workspace || 'spot'), tokenData.access_token, expiresAt, orgTargetUrn, orgInfo.localizedName || '']
    )
    res.redirect('/?linkedin_company=connected')
  } catch (e) {
    res.send('<p>Fel vid LinkedIn-företagsinloggning: ' + e.message + '. <a href="/">Tillbaka</a></p>')
  }
})
app.get('/api/linkedin/company/status', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureLinkedInCompanyTable()
    // Företagssidan hör till arbetsytan (nyckel ws:<arbetsyta>), inte till en enskild användare
    const r = await getAuthPool().query('SELECT org_name, expires_at FROM linkedin_company_accounts WHERE username=$1', ['ws:' + (s.workspace || 'spot')])
    if (!r.rows.length) return res.json({ connected: false })
    res.json({ connected: true, name: r.rows[0].org_name })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/linkedin/company/disconnect', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureLinkedInCompanyTable()
    await getAuthPool().query('DELETE FROM linkedin_company_accounts WHERE username=$1', ['ws:' + (s.workspace || 'spot')])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/linkedin/company/publish', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { text } = req.body || {}
    if (!text) return res.status(400).json({ error: 'Text saknas' })
    await ensureLinkedInCompanyTable()
    const r = await getAuthPool().query('SELECT access_token, org_urn FROM linkedin_company_accounts WHERE username=$1', ['ws:' + (s.workspace || 'spot')])
    if (!r.rows.length) return res.status(400).json({ error: 'LinkedIn-företagssida är inte ansluten. Anslut den först under Varumärke.' })
    const { access_token, org_urn } = r.rows[0]
    const postRes = await fetch('https://api.linkedin.com/rest/posts', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + access_token,
        'Content-Type': 'application/json',
        'X-Restli-Protocol-Version': '2.0.0',
        'Linkedin-Version': '202609'
      },
      body: JSON.stringify({
        author: org_urn,
        commentary: text,
        visibility: 'PUBLIC',
        distribution: { feedDistribution: 'MAIN_FEED', targetEntities: [], thirdPartyDistributionChannels: [] },
        lifecycleState: 'PUBLISHED',
        isReshareDisabledByAuthor: false
      })
    })
    if (!postRes.ok) { const errText = await postRes.text(); return res.status(500).json({ error: 'LinkedIn avvisade företagsinlägget: ' + errText }) }
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
async function ensureBrandImagesTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS brand_images (id SERIAL PRIMARY KEY, name TEXT, url TEXT, ts BIGINT)"); await getAuthPool().query("ALTER TABLE brand_images ADD COLUMN IF NOT EXISTS workspace TEXT DEFAULT 'spot'") }
app.get('/api/brand-images', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureBrandImagesTable()
    const r = await getAuthPool().query('SELECT id, name, url, ts FROM brand_images WHERE workspace=$1 ORDER BY ts DESC', [s.workspace || 'spot'])
    res.json({ images: r.rows })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/brand-images', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { name, url } = req.body || {}
    if ((s.role || 'admin') !== 'admin') return res.status(403).json({ error: 'Endast admin kan lägga till bilder i bildbanken' })
    if (!url) return res.status(400).json({ error: 'Ingen bild skickades' })
    await ensureBrandImagesTable()
    const ts = Date.now()
    const r = await getAuthPool().query('INSERT INTO brand_images (name,url,ts,workspace) VALUES ($1,$2,$3,$4) RETURNING id', [name || 'bild', url, ts, s.workspace || 'spot'])
    res.json({ ok: true, id: r.rows[0].id, ts })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/brand-images/delete', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.role || 'admin') !== 'admin') return res.status(403).json({ error: 'Endast admin kan ändra varumärket' })
    const { id } = req.body || {}
    await ensureBrandImagesTable()
    await getAuthPool().query('DELETE FROM brand_images WHERE id=$1 AND workspace=$2', [id, s.workspace || 'spot'])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
async function ensureDraftsTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS user_drafts (id SERIAL PRIMARY KEY, username TEXT, data JSONB, ts BIGINT)"); await getAuthPool().query('ALTER TABLE user_drafts ADD COLUMN IF NOT EXISTS workspace TEXT'); /* gamla utkast utan arbetsyta får skaparens arbetsyta, så att de aldrig syns för andra team */ await getAuthPool().query("UPDATE user_drafts d SET workspace = COALESCE(u.workspace, 'spot') FROM app_users u WHERE d.workspace IS NULL AND d.username = u.username") }
app.get('/api/drafts', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureDraftsTable()
    // Utkast hör till arbetsytan: Spot-admin som visar en kund ser bara kundens utkast. Gamla utkast utan arbetsyta räknas till användarens egen.
    // Alla i arbetsytan ser teamets utkast (inte bara sina egna)
    // Bara den egna arbetsytans utkast. Utkast utan arbetsyta (från huvudadmin) hör till Spot.
    const r = await getAuthPool().query("SELECT id, data, ts, username FROM user_drafts WHERE workspace=$1 OR (workspace IS NULL AND $1='spot') ORDER BY ts DESC", [s.workspace || 'spot'])
    res.json({ drafts: r.rows.map(row => Object.assign({}, row.data, { id: row.id, ts: row.ts, by: (row.data && row.data.by) || row.username || '' })) })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/drafts', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const draft = req.body || {}
    draft.by = [s.firstName, s.lastName].filter(Boolean).join(' ') || s.u || ''
    await ensureDraftsTable()
    const ts = Date.now()
    const r = await getAuthPool().query('INSERT INTO user_drafts (username,data,ts,workspace) VALUES ($1,$2,$3,$4) RETURNING id', [s.u, JSON.stringify(draft), ts, s.workspace || 'spot'])
    res.json({ ok: true, id: r.rows[0].id, ts })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/drafts/delete', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.role || 'admin') !== 'admin') return res.status(403).json({ error: 'Endast admin kan radera utkast' })
    const { id } = req.body || {}
    await ensureDraftsTable()
    await getAuthPool().query("DELETE FROM user_drafts WHERE id=$1 AND (workspace=$2 OR (workspace IS NULL AND $2='spot'))", [id, s.workspace || 'spot'])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
async function ensureBrandTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS workspace_brand (workspace TEXT PRIMARY KEY, data JSONB)") }
app.get('/api/brand', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureBrandTable()
    const r = await getAuthPool().query('SELECT data FROM workspace_brand WHERE workspace=$1', [s.workspace || 'spot'])
    res.json({ brand: r.rows[0] ? r.rows[0].data : null })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
// Google Fonts-lista till Varumärke → Typografi. Officiellt API om GOOGLE_FONTS_API_KEY finns, annars Googles öppna metadata. Cachas ett dygn.
let _gfCache = null, _gfAt = 0
app.get('/api/google-fonts', auth, async (req, res) => {
  try {
    if (_gfCache && Date.now() - _gfAt < 24 * 3600 * 1000) return res.json({ fonts: _gfCache })
    let fonts = []
    const key = process.env.GOOGLE_FONTS_API_KEY
    if (key) {
      const d = await (await fetch('https://www.googleapis.com/webfonts/v1/webfonts?sort=popularity&key=' + encodeURIComponent(key))).json()
      fonts = (d.items || []).map(f => ({ family: f.family, category: f.category, weights: (f.variants || []).map(v => v === 'regular' ? '400' : v).filter(v => /^\d{3}$/.test(v)) }))
    } else {
      const txt = await (await fetch('https://fonts.google.com/metadata/fonts')).text()
      const d = JSON.parse(txt.replace(/^\)\]\}'\s*/, ''))
      fonts = (d.familyMetadataList || []).map(f => ({ family: f.family, category: (f.category || '').toLowerCase(), weights: Object.keys(f.fonts || {}).filter(v => /^\d{3}$/.test(v)) }))
    }
    fonts = fonts.filter(f => f.family).map(f => ({ family: f.family, category: f.category, weights: Array.from(new Set(f.weights)).sort() }))
    if (fonts.length) { _gfCache = fonts; _gfAt = Date.now() }
    res.json({ fonts })
  } catch (e) { res.status(502).json({ error: 'Kunde inte hämta Google Fonts: ' + e.message, fonts: [] }) }
})
app.post('/api/brand', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.role || 'admin') !== 'admin') return res.status(403).json({ error: 'Endast admin kan ändra varumärket' })
    const incoming = req.body || {}
    const workspace = s.workspace || 'spot'
    await ensureBrandTable()
    const pool = getAuthPool()
    const existingRes = await pool.query('SELECT data FROM workspace_brand WHERE workspace=$1', [workspace])
    const existing = (existingRes.rows[0] && existingRes.rows[0].data) || {}
    // Merge instead of blind overwrite: a field that is missing, undefined, or an empty array
    // in the incoming payload will NOT wipe out previously saved data for that field.
    const merged = Object.assign({}, existing)
    for (const key of Object.keys(incoming)) {
      const val = incoming[key]
      if (val === undefined) continue
      if (Array.isArray(val) && val.length === 0 && Array.isArray(existing[key]) && existing[key].length > 0) continue
      merged[key] = val
    }
    await pool.query('INSERT INTO workspace_brand (workspace,data) VALUES ($1,$2) ON CONFLICT (workspace) DO UPDATE SET data=$2', [workspace, JSON.stringify(merged)])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/brand/fetch-website', auth, async (req, res) => {
  try {
    if (((sessions[getToken(req)] || {}).role || 'admin') !== 'admin') return res.status(403).json({ error: 'Endast admin kan ändra varumärket' })
    let { url } = req.body || {}
    if (!url || typeof url !== 'string') return res.status(400).json({ error: 'URL saknas' })
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url
    let parsed
    try { parsed = new URL(url) } catch (e) { return res.status(400).json({ error: 'Ogiltig URL' }) }
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 8000)
    let html = ''
    try {
      const r = await fetch(parsed.toString(), { signal: controller.signal, headers: { 'User-Agent': 'Mozilla/5.0 (SpotBrandStudio)' } })
      html = await r.text()
    } finally { clearTimeout(timeout) }
    html = html.slice(0, 500000)
    const titleMatch = /<title[^>]*>([^<]*)<\/title>/i.exec(html)
    const descMatch = /<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i.exec(html) || /<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i.exec(html)
    const ogTitleMatch = /<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']*)["']/i.exec(html)
    const ogDescMatch = /<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']*)["']/i.exec(html)
    const decode = (s) => (s || '').replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').trim()
    res.json({
      url: parsed.toString(),
      title: decode(titleMatch ? titleMatch[1] : (ogTitleMatch ? ogTitleMatch[1] : '')),
      description: decode(descMatch ? descMatch[1] : (ogDescMatch ? ogDescMatch[1] : ''))
    })
  } catch (e) { res.status(500).json({ error: e.message || 'Kunde inte hämta sidan' }) }
})
app.post('/api/admin/create-workspace', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.realWorkspace || s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin kan skapa nya arbetsytor' })
    const { companyName, adminUsername, adminPassword, adminFirstName, adminLastName } = req.body || {}
    if (!companyName || !adminUsername || !adminPassword) return res.status(400).json({ error: 'Företagsnamn, användarnamn och lösenord krävs' })
    if (passwordError(adminPassword)) return res.status(400).json({ error: passwordError(adminPassword) })
    await ensureUsersTable()
    const workspaceId = slugBase(companyName).replace(/[^\p{L}\p{N}]+/gu, '-').replace(/(^-|-$)/g, '') || 'workspace' + Date.now()
    const username = slugBase(adminUsername).replace(/[^\p{L}\p{N}]/gu, '')
    const existing = await getAuthPool().query('SELECT 1 FROM app_users WHERE username=$1', [username])
    if (existing.rows.length) return res.status(400).json({ error: 'Användarnamnet är upptaget' })
    await getAuthPool().query(
      'INSERT INTO app_users (username,password,role,first_name,last_name,workspace) VALUES ($1,$2,$3,$4,$5,$6)',
      [username, hashPassword(adminPassword), 'admin', adminFirstName || companyName, adminLastName || '', workspaceId]
    )
    res.json({ ok: true, workspaceId, username })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.get('/api/export-workspace', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const ws = s.workspace || 'spot'
    await ensureBrandTable(); await ensureBrandImagesTable(); await ensureDraftsTable(); await ensureUsersTable()
    const brandRow = await getAuthPool().query('SELECT data FROM workspace_brand WHERE workspace=$1', [ws])
    const images = await getAuthPool().query('SELECT name, url, ts FROM brand_images WHERE workspace=$1', [ws])
    const drafts = await getAuthPool().query('SELECT data, ts FROM user_drafts WHERE username IN (SELECT username FROM app_users WHERE workspace=$1)', [ws])
    const members = await getAuthPool().query('SELECT username, role, first_name, last_name, email FROM app_users WHERE workspace=$1', [ws])
    const { Pool } = require('pg')
    const pgPool = getAuthPool()
    let posts = []
    try {
      const pr = await pgPool.query("SELECT data FROM posts WHERE data->>'workspace' = $1", [ws])
      posts = pr.rows.map(r => r.data)
    } catch (e) {}
    res.json({
      workspace: ws,
      exportedAt: new Date().toISOString(),
      brand: brandRow.rows[0] ? brandRow.rows[0].data : null,
      images: images.rows,
      drafts: drafts.rows.map(r => Object.assign({}, r.data, { ts: r.ts })),
      posts,
      members: members.rows
    })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.get('/api/admin/workspaces', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.realWorkspace || s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    await ensureUsersTable()
    const r = await getAuthPool().query('SELECT workspace, COUNT(*) as members FROM app_users GROUP BY workspace ORDER BY workspace')
    res.json({ workspaces: r.rows })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/admin/view-workspace', auth, async (req, res) => {
  try {
    const t = getToken(req)
    const s = sessions[t] || {}
    if ((s.realWorkspace || s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    const target = String((req.body || {}).workspace || 'spot')
    if (target === 'spot') {
      s.workspace = 'spot'
      delete s.realWorkspace
    } else {
      await ensureUsersTable()
      const r = await getAuthPool().query('SELECT 1 FROM app_users WHERE workspace=$1 LIMIT 1', [target])
      if (!r.rows.length) return res.status(404).json({ error: 'Arbetsytan finns inte' })
      s.realWorkspace = 'spot'
      s.workspace = target
    }
    sessions[t] = s
    persistSession(t, s)
    res.json({ ok: true, workspace: s.workspace })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/admin/delete-workspace', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.realWorkspace || s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    const { workspaceId } = req.body || {}
    if (!workspaceId || workspaceId === 'spot') return res.status(400).json({ error: 'Ogiltig eller skyddad arbetsyta' })
    await ensureUsersTable(); await ensureBrandTable(); await ensureBrandImagesTable(); await ensureDraftsTable()
    await getAuthPool().query('DELETE FROM user_channels WHERE username IN (SELECT username FROM app_users WHERE workspace=$1)', [workspaceId])
    await getAuthPool().query('DELETE FROM linkedin_accounts WHERE username IN (SELECT username FROM app_users WHERE workspace=$1)', [workspaceId])
    await getAuthPool().query('DELETE FROM linkedin_company_accounts WHERE username=$2 OR username IN (SELECT username FROM app_users WHERE workspace=$1)', [workspaceId, 'ws:' + workspaceId]).catch(()=>{})
    await getAuthPool().query('DELETE FROM user_drafts WHERE username IN (SELECT username FROM app_users WHERE workspace=$1)', [workspaceId])
    await getAuthPool().query('DELETE FROM brand_images WHERE workspace=$1', [workspaceId])
    await getAuthPool().query('DELETE FROM workspace_brand WHERE workspace=$1', [workspaceId])
    try {
      const { Pool } = require('pg')
      const pgPool = getAuthPool()
      await pgPool.query("DELETE FROM posts WHERE data->>'workspace' = $1", [workspaceId])
    } catch (e) {}
    await getAuthPool().query('DELETE FROM app_users WHERE workspace=$1', [workspaceId])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/delete-post', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { id } = req.body || {}
    if (!id) return res.status(400).json({ error: 'id saknas' })
    const { Pool } = require('pg')
    const pool = getAuthPool()
    await pool.query("UPDATE posts SET data = jsonb_set(jsonb_set(data,'{deleted}','true'::jsonb,true),'{deletedAt}', to_jsonb($3::bigint), true) WHERE id=$1 AND data->>'workspace' = $2", [String(id), s.workspace || 'spot', Date.now()])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.get('/api/trash-posts', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { Pool } = require('pg')
    const pool = getAuthPool()
    await pool.query('CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, data JSONB, created_at TIMESTAMPTZ DEFAULT NOW())')
    const r = await pool.query("SELECT data FROM posts WHERE data->>'workspace' = $1 AND data->>'deleted' = 'true' ORDER BY created_at DESC LIMIT 200", [s.workspace || 'spot'])
    res.json({ posts: r.rows.map(function(x){ return x.data }) })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/restore-post', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { id } = req.body || {}
    if (!id) return res.status(400).json({ error: 'id saknas' })
    const { Pool } = require('pg')
    const pool = getAuthPool()
    await pool.query("UPDATE posts SET data = (data - 'deleted' - 'deletedAt') WHERE id=$1 AND data->>'workspace' = $2", [String(id), s.workspace || 'spot'])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/purge-post', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { id } = req.body || {}
    if (!id) return res.status(400).json({ error: 'id saknas' })
    const { Pool } = require('pg')
    const pool = getAuthPool()
    await pool.query("DELETE FROM posts WHERE id=$1 AND data->>'workspace' = $2", [String(id), s.workspace || 'spot'])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
async function ensurePricingTable() {
  await getAuthPool().query("CREATE TABLE IF NOT EXISTS billing_pricing (workspace TEXT PRIMARY KEY, price_per_user NUMERIC, base_fee NUMERIC, currency TEXT)")
}
const DEFAULT_PRICE_PER_USER = 199
const DEFAULT_BASE_FEE = 0
app.get('/api/admin/billing-summary', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.realWorkspace || s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    await ensureUsersTable(); await ensurePricingTable()
    const counts = await getAuthPool().query("SELECT workspace, COUNT(*) AS members FROM app_users GROUP BY workspace ORDER BY workspace")
    const pricing = await getAuthPool().query('SELECT workspace, price_per_user, base_fee, currency FROM billing_pricing')
    const pmap = {}
    pricing.rows.forEach(function(r){ pmap[r.workspace] = r })
    const defRow = pmap['__default__'] || {}
    const defPrice = defRow.price_per_user !== undefined && defRow.price_per_user !== null ? Number(defRow.price_per_user) : DEFAULT_PRICE_PER_USER
    const defBase = defRow.base_fee !== undefined && defRow.base_fee !== null ? Number(defRow.base_fee) : DEFAULT_BASE_FEE
    const rows = counts.rows.filter(function(c){ return c.workspace !== 'spot' }).map(function(c){
      const p = pmap[c.workspace] || {}
      const pricePerUser = p.price_per_user !== undefined && p.price_per_user !== null ? Number(p.price_per_user) : defPrice
      const baseFee = p.base_fee !== undefined && p.base_fee !== null ? Number(p.base_fee) : defBase
      const members = parseInt(c.members, 10)
      return { workspace: c.workspace, members: members, pricePerUser: pricePerUser, baseFee: baseFee, currency: p.currency || 'SEK', total: baseFee + members * pricePerUser }
    })
    res.json({ rows, defaults: { pricePerUser: defPrice, baseFee: defBase } })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/admin/billing-pricing', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.realWorkspace || s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    const { workspace, pricePerUser, baseFee } = req.body || {}
    const target = workspace || '__default__'
    await ensurePricingTable()
    await getAuthPool().query(
      "INSERT INTO billing_pricing (workspace,price_per_user,base_fee,currency) VALUES ($1,$2,$3,'SEK') ON CONFLICT (workspace) DO UPDATE SET price_per_user=$2, base_fee=$3",
      [target, Number(pricePerUser) || 0, Number(baseFee) || 0]
    )
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
async function ensureBillingTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS billing_events (id SERIAL PRIMARY KEY, workspace TEXT, event_type TEXT, details JSONB, ts BIGINT, seen BOOLEAN DEFAULT FALSE)") }
function logBillingEvent(workspace, eventType, details) {
  ensureBillingTable()
    .then(function(){ return getAuthPool().query('INSERT INTO billing_events (workspace,event_type,details,ts) VALUES ($1,$2,$3,$4)', [workspace, eventType, JSON.stringify(details||{}), Date.now()]) })
    .catch(function(e){ console.error('[billing] log error:', e.message) })
}
app.get('/api/admin/billing-events', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.realWorkspace || s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    await ensureBillingTable()
    const r = await getAuthPool().query('SELECT id, workspace, event_type, details, ts, seen FROM billing_events ORDER BY ts DESC LIMIT 100')
    const counts = await getAuthPool().query("SELECT workspace, COUNT(*) FILTER (WHERE role IS NOT NULL) AS members FROM app_users GROUP BY workspace")
    res.json({ events: r.rows, memberCounts: counts.rows })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/admin/billing-events/seen', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.realWorkspace || s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    await ensureBillingTable()
    await getAuthPool().query('UPDATE billing_events SET seen=TRUE WHERE seen=FALSE')
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
// ---- Påminnelser via mejl (måndagar kl. 08 svensk tid, en gång per vecka och arbetsyta) ----
// "X inlägg väntar på granskning" -> admin och granskare
// "Inget publicerat på 2 veckor"  -> admin och redaktör
const APP_LINK = process.env.APP_URL || 'https://spot-brand-studio-production.up.railway.app'
function _stockholmNow() {
  const p = {}; new Intl.DateTimeFormat('sv-SE', { timeZone: 'Europe/Stockholm', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', weekday: 'short' }).formatToParts(new Date()).forEach(x => { p[x.type] = x.value })
  return { date: p.year + '-' + p.month + '-' + p.day, hour: parseInt(p.hour, 10), monday: /^mån/i.test(p.weekday || '') }
}
async function buildReminders() {
  const pool = getAuthPool()
  await ensureUsersTable()
  await pool.query('CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, data JSONB, created_at TIMESTAMPTZ DEFAULT NOW())')
  const notDeleted = "(data->>'deleted' IS NULL OR data->>'deleted' <> 'true')"
  const rev = await pool.query("SELECT data->>'workspace' AS ws, COUNT(*)::int AS n FROM posts WHERE data->>'status' = 'review' AND " + notDeleted + " GROUP BY 1")
  const pub = await pool.query("SELECT data->>'workspace' AS ws, MAX(created_at) AS last, COUNT(*)::int AS n FROM posts WHERE data->>'status' IN ('published','archived') AND " + notDeleted + " GROUP BY 1")
  const any = await pool.query("SELECT DISTINCT data->>'workspace' AS ws FROM posts WHERE " + notDeleted)
  const users = await pool.query("SELECT username, email, role, first_name, COALESCE(workspace,'spot') AS ws FROM app_users WHERE email IS NOT NULL AND email <> ''")
  const out = []
  const twoWeeks = Date.now() - 14 * 24 * 3600 * 1000
  const lastPub = {}; pub.rows.forEach(r => { lastPub[r.ws || 'spot'] = r.last })
  const waiting = {}; rev.rows.forEach(r => { waiting[r.ws || 'spot'] = r.n })
  any.rows.forEach(r => {
    const ws = r.ws || 'spot'
    const lines = { review: null, quiet: null }
    if (waiting[ws] > 0) lines.review = waiting[ws] + (waiting[ws] === 1 ? ' inlägg väntar' : ' inlägg väntar') + ' på granskning'
    const lp = lastPub[ws] ? new Date(lastPub[ws]).getTime() : 0
    if (lp < twoWeeks) lines.quiet = lp ? 'Inget publicerat på ' + Math.floor((Date.now() - lp) / (7 * 24 * 3600 * 1000)) + ' veckor' : 'Inget har publicerats än'
    users.rows.filter(u => u.ws === ws).forEach(u => {
      const role = u.role || 'admin', msgs = []
      if (lines.review && (role === 'admin' || role === 'granskare')) msgs.push(lines.review)
      if (lines.quiet && (role === 'admin' || role === 'redaktor')) msgs.push(lines.quiet)
      if (msgs.length) out.push({ ws, to: u.email, name: u.first_name || u.username, msgs })
    })
  })
  return out
}
async function sendReminderMail(r) {
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]))
  return sendAppMail({
    to: r.to,
    subject: r.msgs[0],
    text: 'Hej ' + r.name + '!\n\n' + r.msgs.map(m => '- ' + m).join('\n') + '\n\nLogga in: ' + APP_LINK + '\n\nDu får det här mejlet varje måndag när något behöver göras.',
    html: '<p>Hej ' + esc(r.name) + '!</p><ul>' + r.msgs.map(m => '<li><strong>' + esc(m) + '</strong></li>').join('') + '</ul><p><a href="' + APP_LINK + '">Öppna spot. Brand Studio</a></p><p style="color:#888;font-size:12px">Du får det här mejlet varje måndag när något behöver göras.</p>'
  })
}
async function runWeeklyReminders() {
  try {
    const now = _stockholmNow()
    if (!now.monday || now.hour < 8) return
    const pool = getAuthPool()
    await pool.query('CREATE TABLE IF NOT EXISTS reminder_log (week TEXT PRIMARY KEY, sent_at BIGINT, count INTEGER)')
    // Lås veckan först, så att bara en körning skickar (även vid omstart eller flera instanser)
    const lock = await pool.query('INSERT INTO reminder_log (week, sent_at, count) VALUES ($1,$2,0) ON CONFLICT (week) DO NOTHING RETURNING week', [now.date, Date.now()])
    if (!lock.rows.length) return
    const list = await buildReminders()
    let n = 0
    for (const r of list) { if (await sendReminderMail(r)) n++ }
    await pool.query('UPDATE reminder_log SET count=$2 WHERE week=$1', [now.date, n])
    console.log('[reminders] skickade ' + n + ' av ' + list.length)
  } catch (e) { console.error('[reminders]', e.message) }
}
setInterval(runWeeklyReminders, 15 * 60 * 1000)
setTimeout(runWeeklyReminders, 60 * 1000)
// Förhandsvisning för Spot-admin: visar vilka mejl som skulle gå ut, utan att skicka något
app.get('/api/admin/reminders-preview', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.realWorkspace || s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    res.json({ reminders: await buildReminders() })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
// Testutskick för Spot-admin: skickar ett påminnelsemejl bara till den inloggade adminens egen mejladress
app.post('/api/admin/reminders-test', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.realWorkspace || s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    const u = await getUserByUsername(s.u)
    // Spot-admin är ett fast konto utan mejladress i användartabellen, så då går testet till Spots egen adress
    const testTo = (u && u.email) || process.env.FEEDBACK_EMAIL || 'hello@spotstudio.se'
    const ws = s.workspace || 'spot'
    // Riktiga siffror för arbetsytan, hämtade direkt ur databasen (ingen fast exempeltext)
    const pool = getAuthPool()
    const notDeleted = "(data->>'deleted' IS NULL OR data->>'deleted' <> 'true')"
    const rv = await pool.query("SELECT COUNT(*)::int AS n FROM posts WHERE data->>'workspace' = $1 AND data->>'status' = 'review' AND " + notDeleted, [ws])
    const pb = await pool.query("SELECT MAX(created_at) AS last FROM posts WHERE data->>'workspace' = $1 AND data->>'status' IN ('published','archived') AND " + notDeleted, [ws])
    const waiting = (rv.rows[0] && rv.rows[0].n) || 0, last = pb.rows[0] && pb.rows[0].last ? new Date(pb.rows[0].last).getTime() : 0
    const days = last ? Math.floor((Date.now() - last) / (24 * 3600 * 1000)) : null
    const msgs = [
      waiting + (waiting === 1 ? ' inlägg väntar' : ' inlägg väntar') + ' på granskning',
      last ? (days >= 14 ? 'Inget publicerat på ' + Math.floor(days / 7) + ' veckor' : 'Senast publicerat för ' + days + (days === 1 ? ' dag' : ' dagar') + ' sedan') : 'Inget har publicerats än'
    ]
    const ok = await sendReminderMail({ to: testTo, name: (u && (u.first_name || u.username)) || 'Spot', msgs })
    res.json({ sent: ok, to: testTo, msgs, waiting, lastPublished: last ? new Date(last).toISOString() : null })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
restoreSessions().finally(function(){ app.listen(PORT, () => console.log('spot. running on ' + PORT)) })
const LOGIN_HTML = '<!DOCTYPE html><html lang="sv"><head><meta charset="UTF-8"/><title>spot.</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Segoe UI,sans-serif;background:#0f0f0f;min-height:100vh;display:flex;align-items:center;justify-content:center}.c{background:#fff;border-radius:20px;padding:40px 36px;width:min(380px,92vw);box-shadow:0 24px 60px rgba(0,0,0,.4)}.logo{font-size:28px;font-weight:800;color:#b31e59;margin-bottom:4px}.tag{font-size:13px;color:#9ca3af;margin-bottom:32px}.f{margin-bottom:16px}label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:6px}input{width:100%;padding:11px 14px;border:1.5px solid #e5e7eb;border-radius:10px;font-size:15px;outline:none;font-family:inherit}input:focus{border-color:#b31e59}.err{color:#b31e59;font-size:13px;margin-top:8px;display:none}.err.show{display:block}button{width:100%;margin-top:8px;padding:13px;background:#b31e59;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;font-family:inherit}</style></head><body><div class="c"><div class="logo">spot.</div><div class="tag">content studio</div><form method="POST" action="/login"><div class="f"><label>Användarnamn eller e-post</label><input type="text" name="username" autofocus/></div><div class="f"><label>Lösenord</label><input type="password" name="password"/></div><div class="err" id="err">Fel.</div><button type="submit">Logga in</button><div style="text-align:center;margin-top:14px"><a href="/forgot" style="font-size:12px;color:#9ca3af;text-decoration:none">Glömt lösenord?</a></div><div class="ok" id="ok" style="display:none;color:#16a34a;font-size:13px;margin-top:8px;text-align:center">Lösenordet är återställt. Logga in med det nya lösenordet.</div></form></div><script>var q=new URLSearchParams(location.search);if(q.get("err"))document.getElementById("err").classList.add("show");if(q.get("reset"))document.getElementById("ok").style.display="block"<\/script></body></html>'
 
const FORGOT_HTML = '<!DOCTYPE html><html lang="sv"><head><meta charset="UTF-8"/><title>spot. - Glömt lösenord</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Segoe UI,sans-serif;background:#0f0f0f;min-height:100vh;display:flex;align-items:center;justify-content:center}.c{background:#fff;border-radius:20px;padding:40px 36px;width:min(380px,92vw);box-shadow:0 24px 60px rgba(0,0,0,.4)}.logo{font-size:28px;font-weight:800;color:#b31e59;margin-bottom:4px}.tag{font-size:13px;color:#9ca3af;margin-bottom:24px;line-height:1.5}.f{margin-bottom:16px}label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:6px}input{width:100%;padding:11px 14px;border:1.5px solid #e5e7eb;border-radius:10px;font-size:15px;outline:none;font-family:inherit}input:focus{border-color:#b31e59}.msg{font-size:13px;margin-top:8px;display:none;padding:10px 12px;border-radius:8px}.msg.err{color:#b31e59;background:#fff5f7}.msg.ok{color:#16a34a;background:#f0fdf4}.msg.show{display:block}button{width:100%;margin-top:8px;padding:13px;background:#b31e59;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;font-family:inherit}a.back{display:block;text-align:center;margin-top:14px;font-size:12px;color:#9ca3af;text-decoration:none}</style></head><body><div class="c"><div class="logo">spot.</div><div class="tag">Vi skickar en länk för att återställa lösenordet till adminens e-postadress.</div><form method="POST" action="/forgot"><div class="f"><label>E-postadress</label><input type="email" name="email" autofocus required placeholder="din@epost.se"/></div><div class="msg err" id="err">Något gick fel. Försök igen.</div><div class="msg err" id="nocfg">Ingen återställnings-e-post är konfigurerad. Kontakta utvecklaren.</div><div class="msg err" id="nomailer">E-postutskick är inte konfigurerat på servern. Kontakta utvecklaren.</div><div class="msg err" id="nomatch">Ingen adminadress matchar den e-postadressen.</div><div class="msg ok" id="sent">Ett mail med en återställningslänk har skickats. Kolla inkorgen (giltig i 30 minuter).</div><button type="submit">Skicka återställningslänk</button></form><a class="back" href="/login">Tillbaka till inloggning</a></div><script>var q=new URLSearchParams(location.search);var e=q.get("err");if(e==="1")document.getElementById("err").classList.add("show");if(e==="nocfg")document.getElementById("nocfg").classList.add("show");if(e==="nomailer")document.getElementById("nomailer").classList.add("show");if(e==="nomatch")document.getElementById("nomatch").classList.add("show");if(q.get("sent"))document.getElementById("sent").classList.add("show")<\/script></body></html>'
const RESET_HTML = '<!DOCTYPE html><html lang="sv"><head><meta charset="UTF-8"/><title>spot. - Nytt lösenord</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Segoe UI,sans-serif;background:#0f0f0f;min-height:100vh;display:flex;align-items:center;justify-content:center}.c{background:#fff;border-radius:20px;padding:40px 36px;width:min(380px,92vw);box-shadow:0 24px 60px rgba(0,0,0,.4)}.logo{font-size:28px;font-weight:800;color:#b31e59;margin-bottom:4px}.tag{font-size:13px;color:#9ca3af;margin-bottom:24px}.f{margin-bottom:16px}label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:6px}input{width:100%;padding:11px 14px;border:1.5px solid #e5e7eb;border-radius:10px;font-size:15px;outline:none;font-family:inherit}input:focus{border-color:#b31e59}.err{color:#b31e59;font-size:13px;margin-top:8px;display:none}.err.show{display:block}button{width:100%;margin-top:8px;padding:13px;background:#b31e59;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;font-family:inherit}</style></head><body><div class="c"><div class="logo">spot.</div><div class="tag">Välj ett nytt lösenord.</div><form method="POST" action="/reset"><input type="hidden" name="token" value="__TOKEN__"/><div class="f"><label>Nytt lösenord</label><input type="password" name="newPassword" autofocus/></div><div class="err" id="err">Minst 6 tecken, 1 versal och 1 specialtecken.</div><button type="submit">Spara nytt lösenord</button></form></div><script>if(new URLSearchParams(location.search).get("err"))document.getElementById("err").classList.add("show")<\/script></body></html>'
const RESET_INVALID_HTML = '<!DOCTYPE html><html lang="sv"><head><meta charset="UTF-8"/><title>spot.</title><style>body{font-family:Segoe UI,sans-serif;background:#0f0f0f;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center}a{color:#b31e59}</style></head><body><div><p>Länken är ogiltig eller har gått ut.</p><p><a href="/forgot">Försök igen</a></p></div></body></html>'
 
