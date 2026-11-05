// Admin dashboard at /admin: Google sign-in limited to config.admin.emails (and
// optionally to config.admin.allowFrom networks), a static single-page UI and a JSON API.
// It shows who logs in to the school SSID (802.1X) and manages the guest SSID keys.
import crypto from 'node:crypto';
import fs from 'node:fs';
import * as google from './google.js';
import { KeyError } from './keys.js';
import { dayOf } from './db.js';
import { qrSvg, wifiQrText } from './qr.js';
import { TtlMap } from './store.js';

export const escapeHtml = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

export function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

const UI_DIR = new URL('./admin-ui/', import.meta.url);
const STATIC = {
  '/admin/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/admin/app.css': ['app.css', 'text/css; charset=utf-8'],
  '/admin/crest.png': ['crest.png', 'image/png'],
  '/admin/crest-128.png': ['crest-128.png', 'image/png'],
  '/admin/inter.woff2': ['inter.woff2', 'font/woff2'],
  '/admin/print.js': ['print.js', 'text/javascript; charset=utf-8'],
};
const GOOGLE_G = `<svg viewBox="0 0 48 48" width="20" height="20" aria-hidden="true"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>`;
const CSP =
  "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const SESSION_TTL = 8 * 3600_000;
const EMAIL_RE = /^[^@\s/]+@[^@\s/]+\.[^@\s/]+$/;

function ipToInt(ip) {
  const p = String(ip).split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

/** Exact IPs or IPv4 CIDR ranges. An empty list allows everyone. */
export function ipAllowed(ip, list) {
  if (!list.length) return true;
  return list.some((entry) => {
    const [base, bits] = String(entry).split('/');
    if (bits === undefined) return base === ip;
    const a = ipToInt(ip);
    const b = ipToInt(base);
    const n = Number(bits);
    if (a === null || b === null || !(n >= 0 && n <= 32)) return false;
    const mask = n === 0 ? 0 : (~0 << (32 - n)) >>> 0;
    return (a & mask) >>> 0 === (b & mask) >>> 0;
  });
}

function readJson(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(Object.assign(new Error('Request too large'), { status: 413 }));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {});
      } catch {
        reject(Object.assign(new Error('Invalid JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

export function createAdmin({ config, db, settings, keys, access, platform = null, log, oauth = google }) {
  // Sites visited (browsing.js) are shown only to the admins in browsing.viewers, or to every admin when that's empty.
  const canSeeSites = (email) => config.browsing.enabled && (!config.browsing.viewers.length || config.browsing.viewers.includes(email));
  const enabled = config.admin.emails.length > 0;
  const adminDomains = [...new Set(config.admin.emails.map((e) => e.split('@')[1]))];
  const secure = config.publicUrl.startsWith('https://');
  const redirectUri = `${config.publicUrl}/admin/oauth/callback`;
  const sessions = new TtlMap();
  const pending = new TtlMap({ max: 2000 }); // sign-ins in progress; anyone can start one
  const files = Object.fromEntries(
    ['index.html', ...Object.values(STATIC).map(([f]) => f)].map((f) => [f, fs.readFileSync(new URL(f, UI_DIR))]),
  );

  // Behind Caddy: the address Caddy saw is the last X-Forwarded-For entry, and the header
  // only counts when the request really came from the proxy on this machine.
  const clientIp = (req) => {
    const peer = (req.socket.remoteAddress ?? '').replace(/^::ffff:/, '');
    const fwd = config.trustProxy && ['127.0.0.1', '::1'].includes(peer) && req.headers['x-forwarded-for'];
    return fwd ? fwd.split(',').pop().trim().replace(/^::ffff:/, '') : peer;
  };
  const cookie = (name, value, maxAge) =>
    `${name}=${value}; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
  const sessionOf = (req) => {
    const id = parseCookies(req.headers.cookie).wp_admin;
    return id ? sessions.get(id) : undefined;
  };

  const baseHeaders = {
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': CSP,
    ...(secure && { 'Strict-Transport-Security': 'max-age=31536000' }),
  };
  function send(res, status, body, type, headers = {}) {
    res.writeHead(status, { ...baseHeaders, 'Content-Type': type, ...headers });
    res.end(body);
  }
  const json = (res, status, data) => send(res, status, JSON.stringify(data), 'application/json; charset=utf-8');
  const redirect = (res, location, headers = {}) => {
    res.writeHead(302, { ...baseHeaders, Location: location, ...headers });
    res.end();
  };

  function loginPage(res, { error, status = 200 } = {}) {
    const name = settings.current().branding.name;
    const { school, motto } = config.branding;
    send(
      res,
      status,
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · ${escapeHtml(name)} admin</title><link rel="icon" href="/admin/crest-128.png"><link rel="stylesheet" href="/admin/app.css"></head>
<body><div class="login-wrap">
<div class="login-hero" aria-hidden="true">
  <img src="/admin/crest.png" alt="">
  ${school ? `<div class="school">${escapeHtml(school)}</div>` : ''}
  ${motto ? `<div class="motto">${escapeHtml(motto)}</div>` : ''}
</div>
<main class="login-side"><div class="login-card">
  <h1>WiFi <span>Admin</span></h1>
  <div class="login-body">
    ${error ? `<p class="notice notice-bad">${escapeHtml(error)}</p>` : `<p class="muted">Manage <strong>${escapeHtml(name)}</strong>. Sign in with your school Google account.</p>`}
    ${enabled ? `<a class="btn-google" href="/admin/login">${GOOGLE_G}<span>Sign in with Google</span></a>` : ''}
  </div>
</div></main>
</div></body></html>`,
      'text/html; charset=utf-8',
    );
  }

  function startLogin(res) {
    const state = google.randomToken();
    pending.set(state, { nonce: google.randomToken(), verifier: google.randomToken(48) }, 600_000);
    const p = pending.get(state);
    redirect(
      res,
      oauth.buildAuthUrl({
        clientId: config.google.clientId,
        redirectUri,
        state,
        nonce: p.nonce,
        codeVerifier: p.verifier,
        allowedDomains: adminDomains,
      }),
      { 'Set-Cookie': cookie('wp_admin_state', state, 600) },
    );
  }

  async function finishLogin(req, res, url) {
    const state = url.searchParams.get('state');
    const p = state && pending.get(state);
    const clearState = cookie('wp_admin_state', '', 0);
    if (!p || parseCookies(req.headers.cookie).wp_admin_state !== state || !url.searchParams.get('code')) {
      return loginPage(res, { error: 'That sign-in expired or was started in another browser. Try again.' });
    }
    pending.delete(state);
    let check;
    try {
      const idToken = await oauth.exchangeCode({
        clientId: config.google.clientId,
        clientSecret: config.google.clientSecret,
        redirectUri,
        code: url.searchParams.get('code'),
        codeVerifier: p.verifier,
      });
      check = google.checkIdToken(google.decodeJwtPayload(idToken), {
        clientId: config.google.clientId,
        nonce: p.nonce,
        allowedDomains: adminDomains,
      });
    } catch (err) {
      log('google_error', { error: err.message, admin: true });
      return loginPage(res, { error: "Couldn't reach Google. Try again." });
    }
    if (!check.ok || !config.admin.emails.includes(check.email)) {
      log('admin_denied', { attempted: check.ok ? check.email : null, reason: check.ok ? 'not an admin' : check.reason, ip: clientIp(req) });
      return loginPage(res, { error: check.ok ? `${check.email} isn't an admin for this dashboard.` : check.userMessage });
    }
    const id = crypto.randomBytes(24).toString('base64url');
    sessions.set(id, { email: check.email, csrf: crypto.randomBytes(24).toString('base64url') }, SESSION_TTL);
    log('admin', { action: 'signed in to the dashboard', by: check.email, ip: clientIp(req) });
    redirect(res, '/admin', { 'Set-Cookie': [cookie('wp_admin', id, SESSION_TTL / 1000), clearState] });
  }

  function settingsView() {
    const { compiledPolicy, ...current } = settings.current();
    return {
      ...current,
      fixed: {
        publicUrl: config.publicUrl,
        schoolSsid: config.radius.ssid,
        defaultDomain: config.radius.defaultDomain,
        sessionHours: Math.round(config.radius.sessionTimeout / 360) / 10,
        fallbackVlan: config.radius.fallbackVlan ?? null,
        guestSsid: config.dpsk.ssid,
        vsz: `${config.dpsk.host}:${config.dpsk.port} (zone ${config.dpsk.zoneId}, WLAN ${config.dpsk.wlanId})`,
        syncHours: config.dpsk.syncHours,
        admins: config.admin.emails,
        allowFrom: config.admin.allowFrom,
        directory: Boolean(config.google.directory?.enabled),
        guestVlanId: config.dpsk.guestVlanId,
        maxGuestDays: config.dpsk.maxGuestDays,
        vszSecurity: keys.status().vsz.security,
        backup: {
          dir: config.backup.dir,
          keep: config.backup.keep,
          drive: config.backup.drive ? { as: config.backup.drive.as, keep: config.backup.drive.keep } : null,
          last: platform?.status().backup ?? null,
        },
        alerts: platform?.status().alerts ?? { enabled: false, to: [] },
      },
    };
  }

  function csv(rows, columns) {
    const cell = (v) => {
      const t = v == null ? '' : String(v);
      // A leading =, +, -, @, tab or CR would run as a formula in Excel.
      const safe = /^[=+\-@\t\r]/.test(t) ? `'${t}` : t;
      return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
    };
    return [columns.join(','), ...rows.map((r) => columns.map((c) => cell(r[c])).join(','))].join('\r\n');
  }

  // Printable slips with the key and QR code, for visitors on the guest SSID. Passphrases are fetched from the vSZ for this page only.
  async function printSlips(res, ids, s) {
    const ssid = config.dpsk.ssid;
    const slips = [];
    for (const id of ids.slice(0, 200)) {
      const key = await keys.reveal(id);
      if (key) slips.push(key);
    }
    log('admin', { action: `printed ${slips.length} key ${slips.length === 1 ? 'slip' : 'slips'}`, by: s.email });
    const date = (ms) => new Date(ms).toLocaleDateString('en-ZA', { day: 'numeric', month: 'long', year: 'numeric' });
    const who = (k) => `Guest, added by ${k.email}`;
    send(
      res,
      200,
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>WiFi key slips</title><link rel="stylesheet" href="/admin/app.css"></head>
<body class="slips-page">
<div class="slips-bar"><strong>${slips.length} WiFi key ${slips.length === 1 ? 'slip' : 'slips'}</strong><button class="btn btn-primary" id="print" type="button">Print</button></div>
<div class="slips">${slips
        .map(
          (k) => `<article class="slip">
  <header><img src="/admin/crest-128.png" alt=""><div><div class="slip-brand">${escapeHtml(settings.current().branding.name)}</div><div class="slip-who">${escapeHtml(who(k))}</div></div></header>
  <div class="slip-body">
    <div class="slip-qr">${qrSvg(wifiQrText({ ssid, passphrase: k.passphrase }), { label: `QR code to join ${ssid}` })}</div>
    <dl>
      <dt>Guest</dt><dd>${escapeHtml(k.label)}</dd>
      <dt>Network</dt><dd>${escapeHtml(ssid)}</dd>
      <dt>Key</dt><dd class="slip-key">${escapeHtml(k.passphrase)}</dd>
      ${k.expires ? `<dt>Works until</dt><dd>${escapeHtml(date(k.expires))}</dd>` : ''}
    </dl>
  </div>
  <p>Scan the code with the phone's camera, or choose ${escapeHtml(ssid)} in WiFi settings and type the key. It works on one device only: the first one that connects with it.</p>
</article>`,
        )
        .join('')}</div>
<script src="/admin/print.js"></script></body></html>`,
      'text/html; charset=utf-8',
    );
  }

  // A printable page for staff and learners: how to connect each kind of device, and
  // what the school records about WiFi use (POPIA). Filled in from the config.
  function guide(res) {
    const e = escapeHtml;
    const domain = config.radius.defaultDomain;
    const nets = Object.entries(config.portal.networks);
    const ssid = nets.map(([n]) => n).join(' / ');
    const name = settings.current().branding.name;
    const days = settings.current().retentionDays;
    const contact = config.alerts.to[0] ?? config.admin.emails[0] ?? '';
    const remember = config.portal.rememberDays;
    const step = (items) => `<ol>${items.map((i) => `<li>${i}</li>`).join('')}</ol>`;
    const which = nets.length > 1
      ? `<ul>${nets.map(([n]) => {
          const rules = settings.current().policy.rules.filter((r) => !r.deny && r.vlanId === config.portal.networks[n]).map((r) => r.name);
          return `<li><strong>${e(n)}</strong>${rules.length ? `: ${e(rules.join(', '))}` : ''}</li>`;
        }).join('')}</ul>`
      : '';
    send(
      res,
      200,
      `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Connecting to ${e(ssid)}</title><link rel="stylesheet" href="/admin/app.css"></head>
<body class="slips-page">
<div class="slips-bar"><strong>Connection guide</strong><button class="btn btn-primary" id="print" type="button">Print</button></div>
<article class="guide">
  <header><img src="/admin/crest-128.png" alt=""><div><div class="slip-brand">${e(config.branding.school || name)}</div><h1>Connecting to ${e(ssid)}</h1></div></header>

  <p class="lead">Sign in with your <strong>school Google account</strong>: your school email address (or just the part before @${e(domain)}) and the password you use for Gmail and Classroom. There's no separate WiFi password and nothing to install.</p>
  ${which ? `<p>Use the network for your group:</p>${which}` : ''}

  <div class="guide-grid">
    <section><h2>Phones, tablets and laptops</h2>${step([
      `Open WiFi settings and tap <strong>${e(nets.length > 1 ? 'your network' : ssid)}</strong>.`,
      "A sign-in page opens by itself. If it doesn't, open any website in the browser.",
      'Type your school email and password, then tap <strong>Connect</strong>.',
      remember > 0 ? `Done. Your device reconnects by itself ${remember >= 60 ? 'for the rest of the term' : `for ${e(remember)} days`}.` : 'Done.',
    ])}</section>

    <section><h2>Stay safe</h2><ul>
      <li>The sign-in page is always at <strong>${e(new URL(config.publicUrl).host)}</strong>, with a padlock in the address bar.</li>
      <li>Never type your password on a page with another address. Tell IT if one asks for it.</li>
      <li>Don't sign in on someone else's device, and don't let others use your account.</li>
    </ul></section>
  </div>

  <section><h2>If it doesn't connect</h2><ul>
    <li><strong>Check your password</strong> by signing in to Gmail. If you changed it, use the new one.</li>
    <li><strong>"Your account uses the … network"</strong>: join that network instead.</li>
    <li><strong>No sign-in page?</strong> Turn WiFi off and on, or open any website such as example.com.</li>
    <li><strong>Still no luck?</strong> Tell IT your school email and the time you tried. They can see why a sign-in was turned away.</li>
    <li><strong>Visitors</strong> without a school account use <strong>${e(config.dpsk.ssid)}</strong> with a key from IT or reception.</li>
  </ul></section>

  <section class="guide-privacy"><h2>What the school records</h2>
    <p>To keep the network safe and working, the WiFi system records your <strong>school email</strong>, your device's <strong>network address (MAC)</strong>, <strong>when</strong> and <strong>where</strong> (which access point) you connected, and <strong>how much data</strong> you used. ${config.browsing.enabled ? "It also records <strong>which websites you visit</strong>: the site's name and when (for example youtube.com at 10:42), not the pages you open or what you type." : "It does <strong>not</strong> record which websites you visit or what you do online."} Your password goes straight to Google to be checked and is never stored.</p>
    <p>These records are deleted automatically after <strong>${e(days)} days</strong>${config.browsing.enabled ? ` (websites after <strong>${e(config.browsing.retentionDays)} days</strong>)` : ''}, are seen only by the school's IT administrators, and are used only to run the WiFi, solve problems and keep use fair. This follows the Protection of Personal Information Act (POPIA) and the school's ICT policy.${contact ? ` Questions: <strong>${e(contact)}</strong>.` : ''}</p>
  </section>
</article>
<script src="/admin/print.js"></script></body></html>`,
      'text/html; charset=utf-8',
    );
  }

  async function api(req, res, url, s) {
    const route = url.pathname.slice('/admin/api'.length);
    const q = url.searchParams;
    const now = Date.now();
    const audit = (action, extra = {}) => log('admin', { action, by: s.email, ...extra });

    if (req.method === 'GET') {
      if (route === '/me') {
        return json(res, 200, {
          email: s.email,
          csrf: s.csrf,
          network: settings.current().branding.name,
          school: config.branding.school,
          motto: config.branding.motto,
          schoolSsid: config.radius.ssid,
          sessionHours: Math.round(config.radius.sessionTimeout / 360) / 10,
          staleMinutes: config.radius.accountingStaleMinutes,
          guestSsid: config.dpsk.ssid,
          guestVlanId: config.dpsk.guestVlanId,
          maxGuestDays: config.dpsk.maxGuestDays,
          directory: Boolean(config.google.directory?.enabled),
          browsing: { enabled: config.browsing.enabled, canView: canSeeSites(s.email), retentionDays: config.browsing.retentionDays },
        });
      }
      if (route === '/overview') {
        const today = new Date(now);
        today.setHours(0, 0, 0, 0);
        return json(res, 200, {
          today: db.counts(today.getTime()),
          keys: db.keyCounts(),
          errors24h: db.countSince('error', now - 86_400_000),
          recentLogins: db.recentLogins(25),
          online: db.onlineNow(now, config.radius.accountingStaleMinutes * 60_000).length,
          usageToday: db.usageReport(dayOf(now), dayOf(now), 0).totals,
          health: {
            ...keys.status(),
            ...(platform?.status() ?? {}),
            radius: platform?.status().radius ?? null,
            recentErrors: db.events({ category: 'error', limit: 8 }),
            directory: Boolean(config.google.directory?.enabled),
          },
        });
      }
      if (route === '/events') {
        const before = q.get('before') ? Number(q.get('before')) : null;
        return json(res, 200, db.events({ category: q.get('category') || null, q: q.get('q') || null, before, limit: 50 }));
      }
      if (route === '/people') return json(res, 200, { people: db.people({ q: q.get('q') || null }), blocked: db.blockedList() });
      const sites = route.match(/^\/people\/([^/]+)\/sites$/);
      if (sites) {
        const email = decodeURIComponent(sites[1]).toLowerCase();
        if (!EMAIL_RE.test(email)) return json(res, 400, { problems: ['Not an email address'] });
        if (!canSeeSites(s.email)) return json(res, 403, { problems: ['Only the admins in browsing.viewers can see sites visited.'] });
        const days = db.browsingDays(email);
        const day = /^\d{4}-\d{2}-\d{2}$/.test(q.get('day') ?? '') ? q.get('day') : (days[0] ?? dayOf(now));
        const from = new Date(`${day}T00:00:00`).getTime();
        // Who looked at whose browsing, and for which day, goes in the audit log.
        audit('viewed sites visited', { email, day });
        return json(res, 200, { email, day, days, sites: db.personSites(email, from, from + 86_400_000), retentionDays: config.browsing.retentionDays });
      }
      if (route === '/sites') {
        if (!canSeeSites(s.email)) return json(res, 403, { problems: ['Only the admins in browsing.viewers can see sites visited.'] });
        const days = { today: 1, week: 7, month: 30 }[q.get('period')] ?? 1;
        const start = new Date(now);
        start.setHours(0, 0, 0, 0);
        return json(res, 200, { top: db.topSites(start.getTime() - (days - 1) * 86_400_000, now + 3_600_000, 50), collector: platform?.status().browsing ?? null });
      }
      if (route.startsWith('/people/')) {
        const email = decodeURIComponent(route.slice('/people/'.length));
        if (!EMAIL_RE.test(email)) return json(res, 400, { problems: ['Not an email address'] });
        return json(res, 200, { ...db.person(email), usage: db.personUsage(email.toLowerCase(), dayOf(now - 29 * 86_400_000)) });
      }
      if (route === '/usage') {
        const days = { today: 1, week: 7, month: 30 }[q.get('period')] ?? 1;
        return json(res, 200, {
          period: q.get('period') || 'today',
          ...db.usageReport(dayOf(now - (days - 1) * 86_400_000), dayOf(now)),
          online: db.onlineNow(now, config.radius.accountingStaleMinutes * 60_000),
          alertGb: settings.current().usageAlertGb,
          accounting: platform?.status().radius?.lastAccounting ?? null,
        });
      }
      if (route === '/settings') return json(res, 200, settingsView());
      if (route === '/guests') return json(res, 200, db.keysOfKind('guest'));
      if (route === '/export/keys.csv') {
        audit('exported the key list');
        const rows = db.allKeys().map((k) => ({ ...k, created: new Date(k.created).toISOString(), expires: k.expires ? new Date(k.expires).toISOString() : '' }));
        return send(res, 200, csv(rows, ['kind', 'email', 'label', 'vlan_id', 'rule', 'mac', 'created', 'expires', 'created_by', 'id']), 'text/csv; charset=utf-8', {
          'Content-Disposition': 'attachment; filename="wifi-keys.csv"',
        });
      }
      if (route === '/export/usage.csv') {
        audit('exported the usage list');
        const rows = db.usageRows(dayOf(now - settings.current().retentionDays * 86_400_000));
        return send(res, 200, csv(rows, ['day', 'who', 'mac', 'bytes_down', 'bytes_up']), 'text/csv; charset=utf-8', {
          'Content-Disposition': 'attachment; filename="wifi-usage.csv"',
        });
      }
      if (route === '/export/logins.csv') {
        audit('exported the login list');
        const rows = db.recentLogins(100_000).map((l) => ({ ...l, first: new Date(l.first).toISOString(), last: new Date(l.last).toISOString() }));
        return send(res, 200, csv(rows, ['email', 'mac', 'vlan_id', 'rule', 'first', 'last', 'count', 'ap']), 'text/csv; charset=utf-8', {
          'Content-Disposition': 'attachment; filename="wifi-logins.csv"',
        });
      }
      return json(res, 404, { problems: ['Not found'] });
    }

    if (req.method !== 'POST') return json(res, 405, { problems: ['Method not allowed'] });
    if (req.headers['x-csrf-token'] !== s.csrf) return json(res, 403, { problems: ['Your session expired. Reload the page.'] });
    const body = await readJson(req);

    const m = route.match(/^\/people\/([^/]+)\/(block|unblock)$/);
    if (m) {
      const email = decodeURIComponent(m[1]).toLowerCase();
      if (!EMAIL_RE.test(email)) return json(res, 400, { problems: ['Not an email address'] });
      if (m[2] === 'block') {
        const reason = String(body.reason ?? '').trim().slice(0, 200);
        db.block(email, reason, s.email, now);
        // Their devices must sign in again, which a blocked person can't.
        const forgotten = db.forgetDevices?.(email) ?? 0;
        audit('blocked', { email, reason, devicesForgotten: forgotten });
      } else {
        db.unblock(email);
        audit('unblocked', { email });
      }
      access.forget(email);
      return json(res, 200, db.person(email));
    }
    if (route === '/settings') {
      const result = settings.update(body);
      if (!result.ok) return json(res, 422, result);
      audit('changed settings', { changed: Object.keys(body) });
      // New rules apply at each device's next login.
      access.forget();
      return json(res, 200, settingsView());
    }
    const k = route.match(/^\/keys\/([^/]+)\/revoke$/);
    if (k) {
      try {
        await keys.revoke(decodeURIComponent(k[1]), { by: s.email, reason: String(body.reason ?? 'revoked by an admin').slice(0, 200) });
      } catch (err) {
        return json(res, 502, { problems: [`The vSZ didn't remove the key: ${err.message}`] });
      }
      return json(res, 200, { ok: true });
    }
    const kr = route.match(/^\/keys\/([^/]+)\/reset$/);
    if (kr) {
      try {
        const fresh = await keys.reset(decodeURIComponent(kr[1]), { by: s.email });
        return fresh ? json(res, 200, { id: fresh.id }) : json(res, 404, { problems: ['That key no longer exists.'] });
      } catch (err) {
        return json(res, 502, { problems: [`The vSZ didn't reset the key: ${err.message}`] });
      }
    }
    const issueFailed = (err) =>
      err instanceof KeyError ? json(res, 422, { problems: [err.message] }) : json(res, 502, { problems: [`The vSZ didn't create the key: ${err.message}`] });
    if (route === '/guests') {
      try {
        const key = await keys.issueGuest({ name: body.name, days: Number(body.days) }, { by: s.email });
        return json(res, 200, { id: key.id });
      } catch (err) {
        return issueFailed(err);
      }
    }
    if (route === '/adopt') {
      try {
        return json(res, 200, await keys.adopt({ by: s.email }));
      } catch (err) {
        return json(res, 502, { problems: [`Couldn't read keys from the vSZ: ${err.message}`] });
      }
    }
    if (route === '/check' && platform?.checks) {
      audit('checked the connections');
      return json(res, 200, { results: await platform.checks.run({ email: body.email !== false }) });
    }
    if (route === '/backup' && platform) {
      try {
        const result = platform.backupNow();
        audit('made a backup');
        return json(res, 200, result);
      } catch (err) {
        return json(res, 500, { problems: [`Backup failed: ${err.message}`] });
      }
    }
    if (route === '/sync') {
      try {
        return json(res, 200, await keys.sync({ by: s.email }));
      } catch (err) {
        return json(res, 502, { problems: [`Sync failed: ${err.message}`] });
      }
    }
    if (route === '/logout') {
      sessions.delete(parseCookies(req.headers.cookie).wp_admin);
      return send(res, 200, '{}', 'application/json', { 'Set-Cookie': cookie('wp_admin', '', 0) });
    }
    return json(res, 404, { problems: ['Not found'] });
  }

  async function handle(req, res, url) {
    if (!ipAllowed(clientIp(req), config.admin.allowFrom)) {
      log('admin_denied', { reason: 'address not allowed', ip: clientIp(req) });
      return send(res, 403, 'The admin dashboard is not available from this network.', 'text/plain; charset=utf-8');
    }
    const p = url.pathname;
    if (STATIC[p]) {
      const [file, type] = STATIC[p];
      return send(res, 200, files[file], type, { 'Cache-Control': 'no-cache' });
    }
    if (!enabled) {
      return loginPage(res, { status: 503, error: 'No admins are set up yet. Add your email to admin.emails in config.json.' });
    }
    if (p === '/admin/login') return startLogin(res);
    if (p === '/admin/oauth/callback') return finishLogin(req, res, url);

    const s = sessionOf(req);
    // Printing slips and exports do work (and are audited) on a GET: only from the
    // dashboard itself, not from a link on another site.
    const crossSite = !['same-origin', 'none', undefined].includes(req.headers['sec-fetch-site']);
    if (crossSite && (p === '/admin/print' || p.startsWith('/admin/api/export/'))) {
      return send(res, 403, 'Open this from the dashboard.', 'text/plain; charset=utf-8');
    }
    if (p === '/admin/guide' && s) return guide(res);
    if (p === '/admin/print' && s) {
      const ids = (url.searchParams.get('ids') ?? '').split(',').filter(Boolean);
      return printSlips(res, ids, s);
    }
    if (p === '/admin' || p === '/admin/') {
      return s ? send(res, 200, files['index.html'], 'text/html; charset=utf-8') : loginPage(res);
    }
    if (p.startsWith('/admin/api/')) {
      if (!s) return json(res, 401, { problems: ['Sign in again.'] });
      try {
        return await api(req, res, url, s);
      } catch (err) {
        if (err.status) return json(res, err.status, { problems: [err.message] });
        throw err;
      }
    }
    return redirect(res, '/admin');
  }

  return { handle, close: () => (sessions.close(), pending.close()) };
}
