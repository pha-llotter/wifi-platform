// The sign-in page for the school networks (open Hotspot / WISPr WLANs on the vSZ):
//   1. The vSZ sends a device that isn't signed in to GET /?client_mac=…&uip=…&ssid=…
//   2. The person types their school email and password, POST /connect
//   3. The password is checked with Google Secure LDAP, then their rule and the network
//   4. The platform issues a one-time ticket and asks the vSZ (WISPr NBI) to log the
//      device in with it; the vSZ sends that to FreeRADIUS, which asks radius-api.js
//   5. The device is remembered, so it reconnects without this page for portal.rememberDays
// There's no Google sign-in button on purpose: Google refuses its sign-in page inside the
// "Log in to network" window phones open, so a plain form is what works everywhere.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { checkNetwork, findNetwork, normalizeUsername } from './access.js';
import { escapeHtml as e } from './admin.js';
import { TtlMap } from './store.js';

const ASSETS = new URL('./admin-ui/', import.meta.url);
const STATIC = {
  '/portal/crest.png': ['crest-128.png', 'image/png'],
  '/portal/inter.woff2': ['inter.woff2', 'font/woff2'],
  '/portal/portal.css': ['portal.css', 'text/css; charset=utf-8'],
  '/portal/portal.js': ['portal.js', 'text/javascript; charset=utf-8'],
};
const CSP = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const VISIT_TTL = 30 * 60_000;
const WINDOW = 15 * 60_000;

function readForm(req, limit = 8_000) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(Object.assign(new Error('form too large'), { status: 413 }));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => resolve(Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')))));
    req.on('error', reject);
  });
}

/** Counts attempts per key within a sliding window. */
function limiter(max, windowMs) {
  const hits = new TtlMap({ max: 50_000 });
  return {
    blocked: (key) => (hits.get(key)?.length ?? 0) >= max,
    hit(key) {
      const now = Date.now();
      const list = (hits.get(key) ?? []).filter((t) => t > now - windowMs);
      list.push(now);
      hits.set(key, list, windowMs);
    },
    clear: (key) => hits.delete(key),
    close: () => hits.close(),
  };
}

export function createPortal({ config, settings, access, verifyPassword, nbi, tickets, log }) {
  const files = Object.fromEntries(Object.values(STATIC).map(([f]) => [f, fs.readFileSync(new URL(f, ASSETS))]));
  const visits = new TtlMap({ max: 20_000 });
  const wrongByEmail = limiter(5, WINDOW); // wrong passwords per account
  const triesByDevice = limiter(10, WINDOW); // any attempts per device
  const networks = config.portal.networks;
  const onlyNetwork = Object.keys(networks).length === 1 ? Object.keys(networks)[0] : null;

  const brand = () => ({ name: settings.current().branding.name, school: config.branding.school, motto: config.branding.motto });

  function send(res, status, html) {
    res.writeHead(status, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': CSP,
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    res.end(html);
  }

  function page(title, body) {
    const b = brand();
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${e(title)} · ${e(b.name)}</title><link rel="icon" href="/portal/crest.png"><link rel="stylesheet" href="/portal/portal.css"></head>
<body><main class="card">
<header><img src="/portal/crest.png" alt="" width="64" height="64"><div><div class="school">${e(b.school || b.name)}</div>${b.motto ? `<div class="motto">${e(b.motto)}</div>` : ''}</div></header>
${body}
</main><script src="/portal/portal.js"></script></body></html>`;
  }

  function signInPage(res, { visit, error = null, email = '', status = 200 }) {
    const ssid = visit.ssid ?? onlyNetwork ?? 'the school WiFi';
    send(res, status, page(`Sign in to ${ssid}`, `
<h1>Sign in to <span>${e(ssid)}</span></h1>
<p class="lead">Use your school Google account.</p>
${error ? `<p class="error" role="alert">${e(error)}</p>` : ''}
<form method="post" action="/connect" autocomplete="on">
  <input type="hidden" name="v" value="${e(visit.id)}">
  <label for="email">School email</label>
  <input id="email" name="email" type="text" inputmode="email" autocapitalize="none" autocorrect="off" spellcheck="false" autocomplete="username" required value="${e(email)}" placeholder="name@${e(config.google.allowedDomains[0] ?? 'school.org')}">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Connect</button>
</form>
<p class="small">The same email and password as Google Classroom and Gmail.</p>`));
  }

  function messagePage(res, status, title, text) {
    send(res, status, page(title, `<h1>${e(title)}</h1><p class="lead">${e(text)}</p>`));
  }

  function connectedPage(res, visit, email) {
    const days = config.portal.rememberDays;
    const remember = days >= 60 ? 'for the rest of the term' : days > 1 ? `for ${days} days` : days === 1 ? 'until tomorrow' : null;
    send(res, 200, page("You're connected", `
<div class="done" aria-hidden="true">✓</div>
<h1>You're connected</h1>
<p class="lead">Signed in as <strong>${e(email)}</strong>${visit.ssid ? ` on <strong>${e(visit.ssid)}</strong>` : ''}.</p>
${remember ? `<p class="small">This device reconnects by itself ${e(remember)}. You can close this page.</p>` : '<p class="small">You can close this page.</p>'}`));
  }

  // GET / from the vSZ's redirect: remember where the device is, then show the form.
  function landing(req, res, url) {
    const q = url.searchParams;
    if (!q.get('client_mac') || !q.get('uip')) {
      return messagePage(res, 200, 'School WiFi', `Connect to ${Object.keys(networks).map((n) => `“${n}”`).join(' or ')} and this sign-in page opens by itself.`);
    }
    const raw = q.get('ssid') || q.get('wlanName') || onlyNetwork;
    const visit = {
      id: crypto.randomBytes(18).toString('base64url'),
      ue: { ip: q.get('uip'), mac: q.get('client_mac'), proxy: q.get('proxy') ?? '0' },
      ssid: findNetwork(networks, raw)?.ssid ?? raw ?? null,
      created: Date.now(),
    };
    visits.set(visit.id, visit, VISIT_TTL);
    return signInPage(res, { visit });
  }

  async function connect(req, res) {
    const form = await readForm(req);
    const visit = visits.get(String(form.v ?? ''));
    if (!visit) return messagePage(res, 400, 'Start again', 'This page has expired. Turn WiFi off and on again, and the sign-in page opens again.');
    const typed = String(form.email ?? '').trim();
    const password = String(form.password ?? '');
    const email = normalizeUsername(typed, config.radius.defaultDomain);
    const again = (error, status = 200) => signInPage(res, { visit, error, email: typed, status });
    if (!email || !password) return again('Type your school email and password.');

    if (triesByDevice.blocked(visit.ue.mac) || wrongByEmail.blocked(email)) {
      log('denied', { email, reason: 'too many sign-in attempts' });
      return again('Too many attempts. Wait 15 minutes and try again.', 429);
    }
    triesByDevice.hit(visit.ue.mac);

    const domain = email.split('@')[1];
    if (!settings.current().allowedDomains.includes(domain)) {
      return again(`Use your school account (…@${config.google.allowedDomains[0]}).`);
    }

    // The password first, so nothing is said about an account to someone who can't sign in as it.
    let checked;
    try {
      checked = await verifyPassword(email, password);
    } catch (err) {
      log('portal_error', { email, error: err.message });
      return again("The school WiFi can't check passwords right now. Try again in a minute.", 503);
    }
    if (!checked.ok) {
      wrongByEmail.hit(email);
      log('denied', { email, reason: checked.reason === 'not found' ? 'no such school account' : 'wrong password on the sign-in page' });
      return again('That email or password is wrong.');
    }
    wrongByEmail.clear(email);

    let decision;
    try {
      decision = await access.check(email);
    } catch (err) {
      log('directory_error', { email, error: err.message });
      return again("The school WiFi can't check your account right now. Try again in a minute.", 503);
    }
    if (!decision.allow) {
      log('denied', { email, reason: decision.reason, orgUnit: decision.orgUnitPath });
      return again(decision.rule?.message ?? "This account can't use the school WiFi.");
    }
    if (visit.ssid) {
      const net = checkNetwork(networks, decision, visit.ssid);
      if (!net.ok) {
        log('denied', { email, reason: net.reason, orgUnit: decision.orgUnitPath });
        return again(net.message);
      }
    }

    const who = decision.email ?? email;
    const ticket = tickets.issue(who, visit.ssid);
    let result;
    try {
      result = await nbi.loginAndWait(visit.ue, who, ticket);
    } catch (err) {
      log('portal_error', { email: who, error: err.message });
      return again("Your password is right, but the WiFi didn't respond. Try again in a minute.", 502);
    }
    if (!result.ok) {
      log('portal_error', { email: who, error: `the vSZ refused the login: ${result.message || `code ${result.code}`}` });
      return again(result.message && /time/i.test(result.message) ? 'That took too long. Try again.' : "Your password is right, but the WiFi didn't let this device on. Turn WiFi off and on, then try again.");
    }
    visits.delete(visit.id);
    return connectedPage(res, visit, who);
  }

  async function handle(req, res, url) {
    const p = url.pathname;
    if (STATIC[p]) {
      const [file, type] = STATIC[p];
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'public, max-age=3600', 'X-Content-Type-Options': 'nosniff' });
      return res.end(files[file]);
    }
    if (p === '/connect' && req.method === 'POST') return connect(req, res);
    if (p === '/' || p === '/connect') return landing(req, res, url);
    if (p === '/connected') return messagePage(res, 200, "You're connected", 'You can close this page.');
    return null;
  }

  return { handle, close: () => (visits.close(), wrongByEmail.close(), triesByDevice.close()) };
}
