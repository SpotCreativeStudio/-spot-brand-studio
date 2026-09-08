'use strict'
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
const UPASS = process.env.APP_PASSWORD || '1234'
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
      'admin', '1234', 'admin', 'Anna', 'Andersson',
      'redaktor', '1234', 'redaktor', 'Erik', 'Eriksson',
      'granskare', '1234', 'granskare', 'Gustav', 'Granberg'
    ])
  }
}
async function getUserByUsername(username) {
  try { await ensureUsersTable(); const r = await getAuthPool().query("SELECT * FROM app_users WHERE username=$1", [username]); return r.rows[0] || null } catch (e) { console.error('[auth] getUserByUsername error:', e.message); return null }
}
async function getPassword() { try { await ensureAuthTable(); const r = await getAuthPool().query("SELECT value FROM app_settings WHERE key='password'"); return (r.rows[0] && r.rows[0].value) || UPASS } catch (e) { console.error('[auth] getPassword error:', e.message); return UPASS } }
async function setPassword(pw) { try { await ensureAuthTable(); const r = await getAuthPool().query("INSERT INTO app_settings (key,value) VALUES ('password',$1) ON CONFLICT (key) DO UPDATE SET value=$1", [pw]); console.log('[auth] setPassword ok, rowCount:', r.rowCount) } catch (e) { console.error('[auth] setPassword error:', e.message) } }
const resetTokens = {}
function makeResetToken() { const t = crypto.randomBytes(24).toString('hex'); resetTokens[t] = Date.now() + 30 * 60 * 1000; return t }
function validResetToken(t) { const exp = resetTokens[t]; return !!exp && exp > Date.now() }
function getMailer() { if (!nodemailer) return null; if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) return null; return nodemailer.createTransport({ host: process.env.SMTP_HOST, port: +(process.env.SMTP_PORT || 587), secure: process.env.SMTP_PORT === '465', auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }, connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 10000 }) }
app.use(express.json({ limit: '20mb' }))
app.use(express.urlencoded({ extended: true }))
const _TPL = { 'tpl-studio.png': '4.png', 'tpl-case-hallanning.png': '5.png', 'tpl-case-gardsstyling.png': '7.png', 'tpl-louisiana.png': '6.png' }
app.get('/assets/:f', (req, res) => { const f = _TPL[req.params.f] || req.params.f; if (f.indexOf('..') !== -1 || f.indexOf('/') !== -1) return res.status(400).end(); const p = path.join(__dirname, 'assets', f); if (fs.existsSync(p)) return res.sendFile(p); res.status(404).end() })
function makeToken() { return crypto.randomBytes(32).toString('hex') }
function getToken(req) { const c = req.headers.cookie || ''; const p = c.split(';').map(x => x.trim()).find(x => x.startsWith('spot_session=')); return p ? p.split('=')[1] : null }
function auth(req, res, next) { if (sessions[getToken(req)]) return next(); if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' }); res.redirect('/login') }
app.get('/login', (_req, res) => res.send(LOGIN_HTML))
app.post('/login', async (req, res) => {
  const { username, password } = req.body
  const u = await getUserByUsername(username)
  if (u && password === u.password) {
    const t = makeToken()
    sessions[t] = { u: u.username, role: u.role, firstName: u.first_name, lastName: u.last_name, workspace: u.workspace || 'spot' }
    persistSession(t, sessions[t])
    res.setHeader('Set-Cookie', 'spot_session=' + t + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + (60*60*24*7))
    return res.redirect('/')
  }
  if (username === UNAME && password === await getPassword()) {
    const t = makeToken()
    sessions[t] = { u: username, role: 'admin', firstName: process.env.APP_USER_FIRSTNAME || 'Spot', lastName: process.env.APP_USER_LASTNAME || 'Admin', workspace: 'spot' }
    persistSession(t, sessions[t])
    res.setHeader('Set-Cookie', 'spot_session=' + t + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + (60*60*24*7))
    return res.redirect('/')
  }
  res.redirect('/login?err=1')
})
app.post('/logout', (req, res) => { const _t = getToken(req); delete sessions[_t]; dropSession(_t); res.setHeader('Set-Cookie', 'spot_session=; Path=/; Max-Age=0'); res.json({ ok: true }) })
app.get('/api/me', auth, (req, res) => { const s = sessions[getToken(req)] || {}; const firstName = s.firstName || 'Spot'; const lastName = s.lastName || 'Admin'; const role = s.role || 'admin'; const initials = (firstName[0]||'') + (lastName[0]||''); res.json({ firstName, lastName, role, workspace: s.workspace || 'spot', initials: initials.toUpperCase() }) })
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
    if (String(password).length < 4) return res.status(400).json({ error: 'Lösenordet måste vara minst 4 tecken' })
    const roleMap = { admin: 'admin', editor: 'redaktor', viewer: 'granskare' }
    const dbRole = roleMap[role] || 'granskare'
    const parts = String(name).trim().split(/\s+/)
    const firstName = parts[0] || name
    const lastName = parts.slice(1).join(' ') || ''
    let username = String(wantedUsername || String(email).split('@')[0]).toLowerCase().replace(/[^a-z0-9]/g, '')
    if (!username) username = String(email).split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '')
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
    await getAuthPool().query('INSERT INTO app_users (username,password,role,first_name,last_name,email,workspace) VALUES ($1,$2,$3,$4,$5,$6,$7)', [username, password, dbRole, firstName, lastName, email, s.workspace || 'spot'])
    logBillingEvent(s.workspace || 'spot', 'member_added', { username, name: (firstName + ' ' + lastName).trim(), role: dbRole, addedBy: s.u })
    res.json({ ok: true, username })
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
    await getAuthPool().query('DELETE FROM app_users WHERE username=$1', [username])
    logBillingEvent(s.workspace || 'spot', 'member_removed', { username, removedBy: s.u })
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/change-password', auth, async (req, res) => { const { currentPassword, newPassword } = req.body || {}; if (!newPassword || String(newPassword).length < 4) return res.status(400).json({ error: 'Nytt lösenord måste vara minst 4 tecken' }); if (currentPassword !== await getPassword()) return res.status(401).json({ error: 'Fel nuvarande lösenord' }); await setPassword(String(newPassword)); res.json({ ok: true }) })
app.get('/forgot', (_req, res) => res.send(FORGOT_HTML))
app.post('/forgot', async (req, res) => {
  try {
    const recoveryEmail = process.env.APP_RECOVERY_EMAIL
    if (!recoveryEmail) return res.redirect('/forgot?err=nocfg')
    const mailer = getMailer()
    if (!mailer) return res.redirect('/forgot?err=nomailer')
    const t = makeResetToken()
    const link = 'https://' + req.get('host') + '/reset?token=' + t
    await mailer.sendMail({
      from: process.env.SMTP_USER,
      to: recoveryEmail,
      subject: 'spot. - Aterstall losenord',
      text: 'Nagon har begart att aterstalla losenordet for spot. Brand Studio.\n\nKlicka pa lanken nedan for att valja ett nytt losenord (giltig i 30 minuter):\n' + link + '\n\nOm det inte var du kan du ignorera detta mail.',
      html: '<p>Någon har begärt att återställa lösenordet för <strong>spot. Brand Studio</strong>.</p><p><a href="' + link + '">Klicka här för att välja ett nytt lösenord</a> (giltig i 30 minuter).</p><p>Om det inte var du kan du ignorera detta mail.</p>'
    })
    res.redirect('/forgot?sent=1')
  } catch (e) { console.error('[forgot] error:', e.message); res.redirect('/forgot?err=1') }
})
app.get('/reset', (req, res) => { const t = req.query.token || ''; if (!validResetToken(t)) return res.send(RESET_INVALID_HTML); res.send(RESET_HTML.split('__TOKEN__').join(t)) })
app.post('/reset', async (req, res) => { const { token, newPassword } = req.body || {}; if (!validResetToken(token)) return res.redirect('/forgot?err=1'); if (!newPassword || String(newPassword).length < 4) return res.redirect('/reset?token=' + token + '&err=1'); await setPassword(String(newPassword)); delete resetTokens[token]; res.redirect('/login?reset=1') })
app.get('/inject.js', (_req, res) => { try { res.setHeader('Content-Type', 'application/javascript'); res.send(fs.readFileSync(path.join(__dirname, 'inject.js'), 'utf-8')) } catch (e) { res.send('// inject.js not found') } })
app.get('/', auth, (req, res) => { try { const html = fs.readFileSync(path.join(__dirname, 'poc.html'), 'utf-8'); const tag = '<script src="/inject.js"></script>'; const idx = html.lastIndexOf('</script>'); const patched = html.slice(0, idx + 9) + tag + html.slice(idx + 9); res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.send(patched) } catch (e) { res.status(500).send('Error: ' + e.message) } })
app.post('/api/generate', auth, async (req, res) => { try { const { channels = ['instagram'], brief = '', brand = null } = req.body; const apiKey = process.env.GEMINI_API_KEY; if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY saknas' }); const chList = Array.isArray(channels) ? channels : [channels]; let brandBlock = ''; if (brand) { brandBlock = ' Varumarkesprofil - foljs strikt: Tonalitet: ' + (brand.tone||'') + '. Visuell stil: ' + (brand.visualStyle||'') + '. Tjanster: ' + (brand.services||'') + '.'; if (brand.dos && brand.dos.length) brandBlock += ' Gor: ' + brand.dos.join('; ') + '.'; if (brand.donts && brand.donts.length) brandBlock += ' Undvik: ' + brand.donts.join('; ') + '.'; if (brand.forbidden) brandBlock += ' Forbjudna ord/fraser: ' + brand.forbidden + '.'; } const brandName = (brand && brand.name) ? (brand.name + (brand.location ? (', ' + brand.location) : '')) : 'spot. creative studio Halmstad'; const prompt = 'Du ar copywriter for ' + brandName + '.' + brandBlock + ' Brief: ' + (brief || ('Generellt om ' + brandName)) + '. Kanaler: ' + chList.join(', ') + '. Generera EXAKT 3 korta forslag max 100 ord. Svara ENDAST med JSON-array: [{"title":"...","content":"...","hashtags":["..."],"cta":"..."},{"title":"...","content":"...","hashtags":["..."],"cta":"..."},{"title":"...","content":"...","hashtags":["..."],"cta":"..."}]'; const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-image-preview:generateContent?key=' + apiKey, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.9, maxOutputTokens: 8192 } }) }); const data = await r.json(); if (data.error) throw new Error('Gemini: ' + data.error.message); let s = (data.candidates?.[0]?.content?.parts?.[0]?.text || '').replace(/```json/g, '').replace(/```/g, '').trim(); s = s.replace(/,(\s*[}\]])/g, '$1'); const start = s.indexOf('['), end = s.lastIndexOf(']'); if (start < 0 || end < 0) throw new Error('Ingen array i svar'); const flat = JSON.parse(s.slice(start, end + 1)); const proposals = {}; chList.forEach(ch => { proposals[ch] = flat }); res.json({ proposals }) } catch (e) { res.status(500).json({ error: e.message }) } })
app.post('/api/generate-image', auth, async (req, res) => { try { const { brief = '', style = 'modern', brand = null } = req.body; const apiKey = process.env.GEMINI_API_KEY; if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY saknas' }); let brandVisual = ''; if (brand) { brandVisual = ' Varumarkets visuella stil (foljs strikt): ' + (brand.visualStyle||'') + '. Fargpalett: ' + (brand.colors||'') + '.'; } const brandNameImg = (brand && brand.name) ? brand.name : 'spot. creative studio Halmstad'; const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-image-preview:generateContent?key=' + apiKey, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ contents: [{ parts: [{ text: 'CRITICAL RULE: absolutely NO text, no letters, no words, no numbers, no captions, no logos and no typography anywhere in the image - it must be a purely visual photo with zero written characters. Professional social media image ' + brandNameImg + '.' + brandVisual + ' Style: ' + style + '. Brief: ' + (brief || 'creative studio') + '.' }] }], generationConfig: { responseModalities: ['IMAGE', 'TEXT'] } }) }); const data = await r.json(); if (data.error) throw new Error('Gemini: ' + data.error.message); const imgPart = (data.candidates?.[0]?.content?.parts || []).find(p => p.inlineData?.mimeType?.startsWith('image/')); if (imgPart) return res.json({ imageUrl: 'data:' + imgPart.inlineData.mimeType + ';base64,' + imgPart.inlineData.data }); res.json({ imageUrl: 'https://placehold.co/1080x1080/c8003c/ffffff?text=spot.' }) } catch (e) { res.status(500).json({ error: e.message }) } })
app.post('/api/save-post', auth, async (req, res) => { try { const s = sessions[getToken(req)] || {}; const { Pool } = require('pg'); const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }); await pool.query('CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, data JSONB, created_at TIMESTAMPTZ DEFAULT NOW())'); const post = req.body; post.workspace = s.workspace || 'spot'; await pool.query('INSERT INTO posts (id,data) VALUES ($1,$2) ON CONFLICT (id) DO UPDATE SET data=$2,created_at=NOW()', [post.id || Date.now().toString(), JSON.stringify(post)]); res.json({ saved: true }) } catch (e) { res.status(500).json({ error: e.message }) } })
app.get('/api/published-posts', auth, async (req, res) => { try { const s = sessions[getToken(req)] || {}; const { Pool } = require('pg'); const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }); await pool.query('CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, data JSONB, created_at TIMESTAMPTZ DEFAULT NOW())'); const result = await pool.query("SELECT data FROM posts WHERE data->>'status' IN ('published','archived') AND data->>'workspace' = $1 AND (data->>'deleted' IS NULL OR data->>'deleted' <> 'true') ORDER BY created_at DESC LIMIT 200", [s.workspace || 'spot']); res.json({ posts: result.rows.map(r => r.data) }) } catch (e) { res.status(500).json({ error: e.message }) } })
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
    const { text, imageDataUrl } = req.body || {}
    if (!text) return res.status(400).json({ error: 'Text saknas' })
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
    const { id } = req.body || {}
    await ensureBrandImagesTable()
    await getAuthPool().query('DELETE FROM brand_images WHERE id=$1 AND workspace=$2', [id, s.workspace || 'spot'])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
async function ensureDraftsTable() { await getAuthPool().query("CREATE TABLE IF NOT EXISTS user_drafts (id SERIAL PRIMARY KEY, username TEXT, data JSONB, ts BIGINT)") }
app.get('/api/drafts', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    await ensureDraftsTable()
    const r = await getAuthPool().query('SELECT id, data, ts FROM user_drafts WHERE username=$1 ORDER BY ts DESC', [s.u])
    res.json({ drafts: r.rows.map(row => Object.assign({}, row.data, { id: row.id, ts: row.ts })) })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/drafts', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const draft = req.body || {}
    await ensureDraftsTable()
    const ts = Date.now()
    const r = await getAuthPool().query('INSERT INTO user_drafts (username,data,ts) VALUES ($1,$2,$3) RETURNING id', [s.u, JSON.stringify(draft), ts])
    res.json({ ok: true, id: r.rows[0].id, ts })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/drafts/delete', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { id } = req.body || {}
    await ensureDraftsTable()
    await getAuthPool().query('DELETE FROM user_drafts WHERE id=$1 AND username=$2', [id, s.u])
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
app.post('/api/brand', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const data = req.body || {}
    await ensureBrandTable()
    await getAuthPool().query('INSERT INTO workspace_brand (workspace,data) VALUES ($1,$2) ON CONFLICT (workspace) DO UPDATE SET data=$2', [s.workspace || 'spot', JSON.stringify(data)])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/admin/create-workspace', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin kan skapa nya arbetsytor' })
    const { companyName, adminUsername, adminPassword, adminFirstName, adminLastName } = req.body || {}
    if (!companyName || !adminUsername || !adminPassword) return res.status(400).json({ error: 'Företagsnamn, användarnamn och lösenord krävs' })
    if (String(adminPassword).length < 4) return res.status(400).json({ error: 'Lösenordet måste vara minst 4 tecken' })
    await ensureUsersTable()
    const workspaceId = String(companyName).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '') || 'workspace' + Date.now()
    const username = String(adminUsername).toLowerCase().replace(/[^a-z0-9]/g, '')
    const existing = await getAuthPool().query('SELECT 1 FROM app_users WHERE username=$1', [username])
    if (existing.rows.length) return res.status(400).json({ error: 'Användarnamnet är upptaget' })
    await getAuthPool().query(
      'INSERT INTO app_users (username,password,role,first_name,last_name,workspace) VALUES ($1,$2,$3,$4,$5,$6)',
      [username, adminPassword, 'admin', adminFirstName || companyName, adminLastName || '', workspaceId]
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
    const pgPool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
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
    if ((s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    await ensureUsersTable()
    const r = await getAuthPool().query('SELECT workspace, COUNT(*) as members FROM app_users GROUP BY workspace ORDER BY workspace')
    res.json({ workspaces: r.rows })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/admin/delete-workspace', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    const { workspaceId } = req.body || {}
    if (!workspaceId || workspaceId === 'spot') return res.status(400).json({ error: 'Ogiltig eller skyddad arbetsyta' })
    await ensureUsersTable(); await ensureBrandTable(); await ensureBrandImagesTable(); await ensureDraftsTable()
    await getAuthPool().query('DELETE FROM user_channels WHERE username IN (SELECT username FROM app_users WHERE workspace=$1)', [workspaceId])
    await getAuthPool().query('DELETE FROM linkedin_accounts WHERE username IN (SELECT username FROM app_users WHERE workspace=$1)', [workspaceId])
    await getAuthPool().query('DELETE FROM user_drafts WHERE username IN (SELECT username FROM app_users WHERE workspace=$1)', [workspaceId])
    await getAuthPool().query('DELETE FROM brand_images WHERE workspace=$1', [workspaceId])
    await getAuthPool().query('DELETE FROM workspace_brand WHERE workspace=$1', [workspaceId])
    try {
      const { Pool } = require('pg')
      const pgPool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
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
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
    await pool.query("UPDATE posts SET data = jsonb_set(jsonb_set(data,'{deleted}','true'::jsonb,true),'{deletedAt}', to_jsonb($3::bigint), true) WHERE id=$1 AND data->>'workspace' = $2", [String(id), s.workspace || 'spot', Date.now()])
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.get('/api/trash-posts', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    const { Pool } = require('pg')
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
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
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
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
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } })
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
    if ((s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
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
    if ((s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
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
    if ((s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    await ensureBillingTable()
    const r = await getAuthPool().query('SELECT id, workspace, event_type, details, ts, seen FROM billing_events ORDER BY ts DESC LIMIT 100')
    const counts = await getAuthPool().query("SELECT workspace, COUNT(*) FILTER (WHERE role IS NOT NULL) AS members FROM app_users GROUP BY workspace")
    res.json({ events: r.rows, memberCounts: counts.rows })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
app.post('/api/admin/billing-events/seen', auth, async (req, res) => {
  try {
    const s = sessions[getToken(req)] || {}
    if ((s.workspace || 'spot') !== 'spot' || s.role !== 'admin') return res.status(403).json({ error: 'Endast spot-admin' })
    await ensureBillingTable()
    await getAuthPool().query('UPDATE billing_events SET seen=TRUE WHERE seen=FALSE')
    res.json({ ok: true })
  } catch (e) { res.status(500).json({ error: e.message }) }
})
restoreSessions().finally(function(){ app.listen(PORT, () => console.log('spot. running on ' + PORT)) })
const LOGIN_HTML = '<!DOCTYPE html><html lang="sv"><head><meta charset="UTF-8"/><title>spot.</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Segoe UI,sans-serif;background:#0f0f0f;min-height:100vh;display:flex;align-items:center;justify-content:center}.c{background:#fff;border-radius:20px;padding:40px 36px;width:min(380px,92vw);box-shadow:0 24px 60px rgba(0,0,0,.4)}.logo{font-size:28px;font-weight:800;color:#b31e59;margin-bottom:4px}.tag{font-size:13px;color:#9ca3af;margin-bottom:32px}.f{margin-bottom:16px}label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:6px}input{width:100%;padding:11px 14px;border:1.5px solid #e5e7eb;border-radius:10px;font-size:15px;outline:none;font-family:inherit}input:focus{border-color:#b31e59}.err{color:#b31e59;font-size:13px;margin-top:8px;display:none}.err.show{display:block}button{width:100%;margin-top:8px;padding:13px;background:#b31e59;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;font-family:inherit}</style></head><body><div class="c"><div class="logo">spot.</div><div class="tag">content studio</div><form method="POST" action="/login"><div class="f"><label>Användarnamn</label><input type="text" name="username" autofocus/></div><div class="f"><label>Lösenord</label><input type="password" name="password"/></div><div class="err" id="err">Fel.</div><button type="submit">Logga in</button><div style="text-align:center;margin-top:14px"><a href="/forgot" style="font-size:12px;color:#9ca3af;text-decoration:none">Glömt lösenord?</a></div><div class="ok" id="ok" style="display:none;color:#16a34a;font-size:13px;margin-top:8px;text-align:center">Lösenordet är återställt. Logga in med det nya lösenordet.</div></form></div><script>var q=new URLSearchParams(location.search);if(q.get("err"))document.getElementById("err").classList.add("show");if(q.get("reset"))document.getElementById("ok").style.display="block"<\/script></body></html>'

const FORGOT_HTML = '<!DOCTYPE html><html lang="sv"><head><meta charset="UTF-8"/><title>spot. - Glömt lösenord</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Segoe UI,sans-serif;background:#0f0f0f;min-height:100vh;display:flex;align-items:center;justify-content:center}.c{background:#fff;border-radius:20px;padding:40px 36px;width:min(380px,92vw);box-shadow:0 24px 60px rgba(0,0,0,.4)}.logo{font-size:28px;font-weight:800;color:#b31e59;margin-bottom:4px}.tag{font-size:13px;color:#9ca3af;margin-bottom:24px;line-height:1.5}.msg{font-size:13px;margin-top:8px;display:none;padding:10px 12px;border-radius:8px}.msg.err{color:#b31e59;background:#fff5f7}.msg.ok{color:#16a34a;background:#f0fdf4}.msg.show{display:block}button{width:100%;margin-top:8px;padding:13px;background:#b31e59;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;font-family:inherit}a.back{display:block;text-align:center;margin-top:14px;font-size:12px;color:#9ca3af;text-decoration:none}</style></head><body><div class="c"><div class="logo">spot.</div><div class="tag">Vi skickar en länk för att återställa lösenordet till adminens e-postadress.</div><form method="POST" action="/forgot"><div class="msg err" id="err">Något gick fel. Försök igen.</div><div class="msg err" id="nocfg">Ingen återställnings-e-post är konfigurerad. Kontakta utvecklaren.</div><div class="msg err" id="nomailer">E-postutskick är inte konfigurerat på servern. Kontakta utvecklaren.</div><div class="msg ok" id="sent">Ett mail med en återställningslänk har skickats. Kolla inkorgen (giltig i 30 minuter).</div><button type="submit">Skicka återställningslänk</button></form><a class="back" href="/login">Tillbaka till inloggning</a></div><script>var q=new URLSearchParams(location.search);var e=q.get("err");if(e==="1")document.getElementById("err").classList.add("show");if(e==="nocfg")document.getElementById("nocfg").classList.add("show");if(e==="nomailer")document.getElementById("nomailer").classList.add("show");if(q.get("sent"))document.getElementById("sent").classList.add("show")<\/script></body></html>'
const RESET_HTML = '<!DOCTYPE html><html lang="sv"><head><meta charset="UTF-8"/><title>spot. - Nytt lösenord</title><style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Segoe UI,sans-serif;background:#0f0f0f;min-height:100vh;display:flex;align-items:center;justify-content:center}.c{background:#fff;border-radius:20px;padding:40px 36px;width:min(380px,92vw);box-shadow:0 24px 60px rgba(0,0,0,.4)}.logo{font-size:28px;font-weight:800;color:#b31e59;margin-bottom:4px}.tag{font-size:13px;color:#9ca3af;margin-bottom:24px}.f{margin-bottom:16px}label{display:block;font-size:12px;font-weight:600;color:#374151;margin-bottom:6px}input{width:100%;padding:11px 14px;border:1.5px solid #e5e7eb;border-radius:10px;font-size:15px;outline:none;font-family:inherit}input:focus{border-color:#b31e59}.err{color:#b31e59;font-size:13px;margin-top:8px;display:none}.err.show{display:block}button{width:100%;margin-top:8px;padding:13px;background:#b31e59;color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;cursor:pointer;font-family:inherit}</style></head><body><div class="c"><div class="logo">spot.</div><div class="tag">Välj ett nytt lösenord.</div><form method="POST" action="/reset"><input type="hidden" name="token" value="__TOKEN__"/><div class="f"><label>Nytt lösenord</label><input type="password" name="newPassword" autofocus/></div><div class="err" id="err">Lösenordet måste vara minst 4 tecken.</div><button type="submit">Spara nytt lösenord</button></form></div><script>if(new URLSearchParams(location.search).get("err"))document.getElementById("err").classList.add("show")<\/script></body></html>'
const RESET_INVALID_HTML = '<!DOCTYPE html><html lang="sv"><head><meta charset="UTF-8"/><title>spot.</title><style>body{font-family:Segoe UI,sans-serif;background:#0f0f0f;color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center}a{color:#b31e59}</style></head><body><div><p>Länken är ogiltig eller har gått ut.</p><p><a href="/forgot">Försök igen</a></p></div></body></html>'
