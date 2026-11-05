// The sign-in page end to end: the vSZ's redirect, the form, the password check, the
// hand-over to the vSZ (NBI), the vSZ's RADIUS login with the one-time ticket, and the
// remembered device reconnecting by MAC. The fake vSZ below does what the real one does:
// it turns the NBI login into the request FreeRADIUS posts to /radius/portal.
import assert from 'node:assert/strict';
import http from 'node:http';
import { after, before, beforeEach, describe, test } from 'node:test';
import { checkNetwork, createAccess, ssidFromCalledStation } from '../src/access.js';
import { createApp } from '../src/app.js';
import { normalizeConfig } from '../src/config.js';
import { openDb } from '../src/db.js';
import { createPortal } from '../src/portal.js';
import { createRadiusApi } from '../src/radius-api.js';
import { createSettings } from '../src/settings.js';
import { createTickets } from '../src/tickets.js';

const TOKEN = 'unit-token-0123456789abcdef';
const auth = `Basic ${Buffer.from(`radius:${TOKEN}`).toString('base64')}`;
const AP = 'AA-BB-CC-00-11-22';
const users = new Map();
const passwords = new Map();
let h;

async function radius(fields) {
  const res = await fetch(`${h.base}/radius/portal`, {
    method: 'POST',
    headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields),
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

before(async () => {
  const config = normalizeConfig({
    publicUrl: 'http://portal.test',
    google: { clientId: 'cid', clientSecret: 'cs', allowedDomains: ['school.org'], directory: { enabled: true, serviceAccountKeyFile: 'x', adminEmail: 'a@school.org' } },
    radius: { apiToken: TOKEN, sessionTimeout: 3600 },
    dpsk: { host: 'vsz', protocol: 'http', username: 'u', password: 'p', zoneId: 'z', wlanId: 'w', ssid: 'Guest' },
    portal: { networks: { Nexus: 10, 'Nexus Staff': 1 }, rememberDays: 90, nbi: { host: 'vsz', protocol: 'http', password: 'nbi' } },
    policy: {
      rules: [
        { name: 'Shared accounts', email: '^exam\\.', deny: true, message: 'Shared accounts stay offline.' },
        { name: 'IT Staff', orgUnit: '/IT Staff', vlanId: 1 },
        { name: 'Staff', orgUnit: '/Staff', vlanId: 1 },
        { name: 'Students', orgUnit: '/Students', vlanId: 10 },
      ],
      default: null,
    },
    branding: { name: 'Nexus WiFi', school: 'Test School' },
    admin: { emails: ['it@school.org'] },
  });
  h = { events: [], nbiCalls: [], nbiDown: false };
  h.config = config;
  h.db = openDb(':memory:');
  h.settings = createSettings({ config, db: h.db });
  h.access = createAccess({ settings: h.settings, directory: { getUser: async (email) => users.get(email) ?? null } });
  const log = (event, data) => {
    h.events.push({ event, ...data });
    h.db.record(event, data);
  };
  h.tickets = createTickets();
  h.radiusApi = createRadiusApi({ config, db: h.db, access: h.access, settings: h.settings, tickets: h.tickets, log });
  const verifyPassword = async (email, password) => {
    if (!passwords.has(email)) return { ok: false, reason: 'not found' };
    return passwords.get(email) === password ? { ok: true, dn: `uid=${email}` } : { ok: false, reason: 'wrong password' };
  };
  // The vSZ: an NBI login becomes a RADIUS Access-Request for that device and network.
  const nbi = {
    async loginAndWait(ue, username, password) {
      h.nbiCalls.push({ ue, username, password });
      if (h.nbiDown) throw new Error('connect ECONNREFUSED');
      const r = await radius({ 'User-Name': username, 'User-Password': password, 'Calling-Station-Id': ue.mac, 'Called-Station-Id': `${AP}:${h.wlan}` });
      return r.status === 200 ? { ok: true, code: 201 } : { ok: false, code: 301, message: r.json?.['reply:Reply-Message'] ?? '' };
    },
  };
  h.portal = createPortal({ config, settings: h.settings, access: h.access, verifyPassword, nbi, tickets: h.tickets, log });
  h.app = createApp({ admin: { handle: async () => {} }, radiusApi: h.radiusApi, portal: h.portal, log });
  h.server = http.createServer(h.app.handle);
  await new Promise((r) => h.server.listen(0, '127.0.0.1', r));
  h.base = `http://127.0.0.1:${h.server.address().port}`;
});

after(() => {
  h.server.close();
  h.radiusApi.close();
  h.portal.close();
  h.tickets.close();
  h.db.close();
});

let macN = 0;
beforeEach(() => {
  users.clear();
  passwords.clear();
  users.set('t.smith@school.org', { email: 't.smith@school.org', orgUnitPath: '/Staff', suspended: false });
  users.set('pupil@school.org', { email: 'pupil@school.org', orgUnitPath: '/Students/Grade 9', suspended: false });
  users.set('exam.room1@school.org', { email: 'exam.room1@school.org', orgUnitPath: '/Staff', suspended: false });
  passwords.set('t.smith@school.org', 'staff-pass');
  passwords.set('pupil@school.org', 'pupil-pass');
  passwords.set('exam.room1@school.org', 'exam-pass');
  h.access.forget();
  h.events.length = 0;
  h.nbiCalls.length = 0;
  h.nbiDown = false;
  h.mac = `02-00-00-00-00-${String(++macN).padStart(2, '0')}`;
});

/** Arrives from the vSZ's redirect on a network, then submits the form. */
async function signIn(wlan, email, password, { ssidParam = wlan } = {}) {
  h.wlan = wlan;
  const q = new URLSearchParams({ client_mac: h.mac, uip: '10.10.0.5', nbiIP: '192.168.1.37', url: 'http://example.com/' });
  if (ssidParam) q.set('ssid', ssidParam);
  const landing = await fetch(`${h.base}/?${q}`);
  const html = await landing.text();
  const v = /name="v" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(v, 'the landing page carries a visit id');
  const res = await fetch(`${h.base}/connect`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ v, email, password }) });
  return { status: res.status, html: await res.text(), landing: html };
}

const reconnect = (wlan, mac = h.mac) => radius({ 'User-Name': mac.replace(/-/g, '').toLowerCase(), 'User-Password': mac.replace(/-/g, '').toLowerCase(), 'Calling-Station-Id': mac, 'Called-Station-Id': `${AP}:${wlan}` });

describe('the sign-in page', () => {
  test('the vSZ redirect shows a form for that network, with no Google button', async () => {
    const r = await signIn('Nexus', 'pupil@school.org', 'pupil-pass');
    assert.match(r.landing, /Sign in to <span>Nexus<\/span>/);
    assert.match(r.landing, /name="password" type="password"/);
    assert.doesNotMatch(r.landing, /accounts\.google\.com/);
  });

  test('a student signs in on Nexus: the vSZ logs the device in with a one-time ticket, not the password', async () => {
    const r = await signIn('Nexus', 'pupil@school.org', 'pupil-pass');
    assert.equal(r.status, 200);
    assert.match(r.html, /You're connected/);
    assert.match(r.html, /rest of the term/);
    const call = h.nbiCalls[0];
    assert.equal(call.username, 'pupil@school.org');
    assert.notEqual(call.password, 'pupil-pass', 'the school password never goes to the vSZ');
    assert.ok(call.password.length >= 24);
    assert.equal(h.db.portalDevice(h.mac)?.email, 'pupil@school.org', 'the device is remembered');
    const signedIn = h.events.find((x) => x.event === 'signed_in');
    assert.equal(signedIn.vlanId, 10);
    assert.equal(signedIn.how, 'sign-in page');
  });

  test('a bare username gets the school domain', async () => {
    const r = await signIn('Nexus Staff', 'T.Smith', 'staff-pass');
    assert.match(r.html, /You're connected/);
    assert.equal(h.nbiCalls[0].username, 't.smith@school.org');
  });

  test('a wrong password is refused without saying whether the account exists', async () => {
    const wrong = await signIn('Nexus', 'pupil@school.org', 'nope');
    const unknown = await signIn('Nexus', 'nobody@school.org', 'nope');
    for (const r of [wrong, unknown]) {
      assert.match(r.html, /That email or password is wrong/);
      assert.match(r.html, /name="password"/, 'the form is shown again');
    }
    assert.equal(h.nbiCalls.length, 0);
    assert.ok(h.events.some((x) => x.event === 'denied' && /wrong password/.test(x.reason)));
  });

  test('a blocked person is told so, with the reason the admin gave, after the password checks out', async () => {
    h.db.block('t.smith@school.org', 'Sharing the password <with others>', 'it@school.org');
    h.access.forget();
    const r = await signIn('Nexus Staff', 't.smith@school.org', 'staff-pass');
    assert.match(r.html, /This account is blocked from the school WiFi\. Reason: Sharing the password &lt;with others&gt;/);
    assert.equal(h.nbiCalls.length, 0);
    const wrong = await signIn('Nexus Staff', 't.smith@school.org', 'nope');
    assert.doesNotMatch(wrong.html, /blocked/, 'nothing is said about a block without the right password');
  });

  test('a block without a reason still says the account is blocked', async () => {
    h.db.block('t.smith@school.org', '', 'it@school.org');
    h.access.forget();
    const r = await signIn('Nexus Staff', 't.smith@school.org', 'staff-pass');
    assert.match(r.html, /This account is blocked from the school WiFi\.<\/p>/);
  });

  test('a student on the staff network is pointed to the right one, after the password checks out', async () => {
    const r = await signIn('Nexus Staff', 'pupil@school.org', 'pupil-pass');
    assert.match(r.html, /Your account uses the “Nexus” network/);
    assert.equal(h.nbiCalls.length, 0);
  });

  test('a deny rule shows its own message', async () => {
    const r = await signIn('Nexus Staff', 'exam.room1@school.org', 'exam-pass');
    assert.match(r.html, /Shared accounts stay offline/);
  });

  test('another domain is turned away before any password check', async () => {
    const r = await signIn('Nexus', 'someone@gmail.com', 'x');
    assert.match(r.html, /Use your school account/);
  });

  test('five wrong passwords lock that account out of the page for a while', async () => {
    passwords.set('locked@school.org', 'right');
    users.set('locked@school.org', { email: 'locked@school.org', orgUnitPath: '/Students', suspended: false });
    for (let i = 0; i < 5; i++) await signIn('Nexus', 'locked@school.org', 'wrong');
    h.mac = '02-00-00-00-01-99'; // even from another device
    const r = await signIn('Nexus', 'locked@school.org', 'right');
    assert.equal(r.status, 429);
    assert.match(r.html, /Too many attempts/);
  });

  test('if the vSZ cannot be reached the person is told, and nothing is remembered', async () => {
    h.nbiDown = true;
    const r = await signIn('Nexus', 'pupil@school.org', 'pupil-pass');
    assert.equal(r.status, 502);
    assert.match(r.html, /didn(&#39;|')t respond/);
    assert.equal(h.db.portalDevice(h.mac), null);
  });

  test('an expired or forged visit starts again', async () => {
    const res = await fetch(`${h.base}/connect`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'v=forged&email=pupil%40school.org&password=pupil-pass' });
    assert.equal(res.status, 400);
    assert.match(await res.text(), /Start again/);
  });

  test('opening the address directly explains what to do', async () => {
    const html = await (await fetch(`${h.base}/`)).text();
    assert.match(html, /Connect to “Nexus” or “Nexus Staff”/);
  });

  test('the page sends a strict CSP and its assets are served', async () => {
    const res = await fetch(`${h.base}/`);
    assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
    for (const p of ['/portal/portal.css', '/portal/portal.js', '/portal/crest.png']) assert.equal((await fetch(h.base + p)).status, 200, p);
  });

  test('the page links its style and script by version, so a changed file is fetched at once', async () => {
    const html = await (await fetch(`${h.base}/`)).text();
    const css = /href="(\/portal\/portal\.css\?v=[0-9a-f]{10})"/.exec(html)?.[1];
    const js = /src="(\/portal\/portal\.js\?v=[0-9a-f]{10})"/.exec(html)?.[1];
    assert.ok(css && js, 'versioned links');
    for (const p of [css, js]) assert.equal((await fetch(h.base + p)).status, 200, p);
  });
});

describe('RADIUS for the sign-in networks', () => {
  test('a ticket works once, for the email it was issued to', async () => {
    const ticket = h.tickets.issue('pupil@school.org', 'Nexus');
    const fields = { 'User-Name': 'pupil@school.org', 'User-Password': ticket, 'Calling-Station-Id': h.mac, 'Called-Station-Id': `${AP}:Nexus` };
    assert.equal((await radius({ ...fields, 'User-Name': 't.smith@school.org' })).status, 401, 'not for another email');
    assert.equal((await radius(fields)).status, 200);
    assert.equal((await radius(fields)).status, 401, 'not twice');
  });

  test('a made-up password is refused', async () => {
    const r = await radius({ 'User-Name': 'pupil@school.org', 'User-Password': 'guess', 'Calling-Station-Id': h.mac, 'Called-Station-Id': `${AP}:Nexus` });
    assert.equal(r.status, 401);
  });

  test('the network is checked again at RADIUS time, from the SSID the vSZ reports', async () => {
    // A ticket issued for Nexus but used on Nexus Staff (say the redirect had no SSID).
    const ticket = h.tickets.issue('pupil@school.org', null);
    const r = await radius({ 'User-Name': 'pupil@school.org', 'User-Password': ticket, 'Calling-Station-Id': h.mac, 'Called-Station-Id': `${AP}:Nexus Staff` });
    assert.equal(r.status, 401);
    assert.match(r.json['reply:Reply-Message'], /Nexus/);
  });

  test('a remembered device reconnects by MAC, with the session length and its owner', async () => {
    await signIn('Nexus', 'pupil@school.org', 'pupil-pass');
    const r = await reconnect('Nexus');
    assert.equal(r.status, 200);
    assert.equal(r.json['reply:Session-Timeout'], 3600);
    assert.equal(r.json['reply:User-Name'], 'pupil@school.org');
  });

  test('a new device gets the sign-in page (refused quietly)', async () => {
    const r = await reconnect('Nexus', '02-00-00-00-09-09');
    assert.equal(r.status, 401);
    assert.equal(h.events.filter((x) => x.event === 'denied').length, 0, 'an unknown device is not an incident');
  });

  test("a student's remembered phone can't use the staff network", async () => {
    await signIn('Nexus', 'pupil@school.org', 'pupil-pass');
    assert.equal((await reconnect('Nexus Staff')).status, 401);
    assert.equal((await reconnect('Nexus')).status, 200);
  });

  test('a remembered device needs the SSID, or it signs in again', async () => {
    await signIn('Nexus', 'pupil@school.org', 'pupil-pass');
    const mac = h.mac.replace(/-/g, '').toLowerCase();
    const r = await radius({ 'User-Name': mac, 'User-Password': mac, 'Calling-Station-Id': h.mac, 'Called-Station-Id': AP });
    assert.equal(r.status, 401);
    assert.ok(h.events.some((x) => x.event === 'portal_ssid_error'));
  });

  test('blocking someone stops their remembered devices and forgets them', async () => {
    await signIn('Nexus Staff', 't.smith@school.org', 'staff-pass');
    h.db.block('t.smith@school.org', 'test', 'it@school.org');
    h.access.forget();
    assert.equal((await reconnect('Nexus Staff')).status, 401);
    assert.equal(h.db.portalDevice(h.mac), null);
  });

  test('a suspended Google account stops reconnecting too', async () => {
    await signIn('Nexus', 'pupil@school.org', 'pupil-pass');
    users.set('pupil@school.org', { email: 'pupil@school.org', orgUnitPath: '/Students', suspended: true });
    h.access.forget();
    assert.equal((await reconnect('Nexus')).status, 401);
  });

  test('usage reported under a MAC is counted for the device owner', async () => {
    await signIn('Nexus', 'pupil@school.org', 'pupil-pass');
    const mac = h.mac.replace(/-/g, '').toLowerCase();
    const res = await fetch(`${h.base}/radius/accounting`, {
      method: 'POST',
      headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ 'User-Name': mac, 'Calling-Station-Id': h.mac, 'Acct-Status-Type': 'Start', 'Acct-Session-Id': `s-${mac}` }),
    });
    assert.equal(res.status, 204);
    assert.ok(h.db.onlineNow().some((s) => s.who === 'pupil@school.org'));
  });
});

describe('networks and SSIDs', () => {
  test('the SSID is read from Called-Station-Id in its usual forms', () => {
    assert.equal(ssidFromCalledStation('AA-BB-CC-DD-EE-FF:Nexus Staff'), 'Nexus Staff');
    assert.equal(ssidFromCalledStation('aa:bb:cc:dd:ee:ff:Nexus'), 'Nexus');
    assert.equal(ssidFromCalledStation('AA-BB-CC-DD-EE-FF'), null);
    assert.equal(ssidFromCalledStation(''), null);
  });

  test('a rule without a VLAN may use any network; an unknown network is refused', () => {
    const nets = { Nexus: 10, 'Nexus Staff': 1 };
    assert.equal(checkNetwork(nets, { vlanId: null }, 'Nexus Staff').ok, true);
    assert.equal(checkNetwork(nets, { vlanId: 10 }, 'nexus').ok, true, 'case does not matter');
    assert.equal(checkNetwork(nets, { vlanId: 10 }, 'Other').ok, false);
  });
});

describe('the vSZ portal interface (NBI) client', () => {
  test('sends the user name and password, and waits while the login is pending', async () => {
    const { createNbiClient } = await import('../src/nbi.js');
    const seen = [];
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const r = JSON.parse(body);
        seen.push(r);
        const code = r.RequestType === 'Login' ? 202 : 101;
        res.end(JSON.stringify({ ResponseCode: code, ReplyMessage: code === 101 ? 'Authorized' : 'Pending' }));
      });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    try {
      const nbi = createNbiClient({ host: '127.0.0.1', port: server.address().port, protocol: 'http', username: 'wifiplatform', password: 'p-1' });
      const r = await nbi.loginAndWait({ ip: 'ENC1', mac: 'ENC2' }, 'pupil@school.org', 'ticket', { intervalMs: 10 });
      assert.equal(r.ok, true);
      assert.equal(seen[0].RequestType, 'Login');
      assert.equal(seen[0].RequestUserName, 'wifiplatform');
      assert.equal(seen[0].RequestPassword, 'p-1');
      assert.equal(seen[0]['UE-MAC'], 'ENC2', 'the redirect values are passed back as they came');
      assert.equal(seen[0]['UE-Password'], 'ticket');
      assert.equal(seen[1].RequestType, 'Status');
    } finally {
      server.close();
    }
  });
});
