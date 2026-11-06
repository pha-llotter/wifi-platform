// The HTTP API FreeRADIUS calls (rlm_rest) during each 802.1X login on the school SSID:
//   POST /radius/authorize               → 200 with the VLAN to put the device on, or 401 to refuse
//   POST /radius/post-auth?result=accept|reject  → recorded for the dashboard
//   POST /radius/accounting              → data used per session (start, updates, stop) for the Usage page
// FreeRADIUS checks the password itself, against Google Secure LDAP. Only FreeRADIUS
// may call this: it must come from an allowed address and carry the shared token.
//   POST /radius/portal                  → a Hotspot (WISPr) login: a sign-in from the portal
//                                          page, or a remembered device reconnecting
import crypto from 'node:crypto';
import { checkNetwork, normalizeUsername, ssidFromCalledStation } from './access.js';
import { ipAllowed } from './admin.js';
import { normalizeMac } from './db.js';
import { guestDisplayName, guestFromVszName } from './keys.js';
import { TtlMap } from './store.js';

const isMac = (s) => /^([0-9a-f]{2}[-:.]?){5}[0-9a-f]{2}$/i.test(String(s ?? '').trim());

// rlm_rest sends request attributes as {"User-Name": {"type": "string", "value": ["…"]}}.
const attr = (body, name) => {
  const v = body?.[name];
  const value = v && typeof v === 'object' && 'value' in v ? v.value : v;
  return Array.isArray(value) ? value[0] : value;
};

const GB = 1024 ** 3;
const int = (v) => {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
};

export function createRadiusApi({ config, db, access, settings, tickets = null, log }) {
  const cfg = config.radius;
  const expected = Buffer.from(`radius:${cfg.apiToken}`).toString('base64');
  const refused = new TtlMap(); // logins this API refused, so the reject callback doesn't log them twice
  const status = { lastRequest: null, lastAccept: null, lastReject: null, lastAccounting: null };

  function allowed(req) {
    const ip = (req.socket.remoteAddress ?? '').replace(/^::ffff:/, '');
    if (req.headers['x-forwarded-for']) return false; // came through the public proxy
    if (!ipAllowed(ip, cfg.apiAllowFrom)) return false;
    const got = Buffer.from(String(req.headers.authorization ?? '').replace(/^Basic /i, ''));
    const want = Buffer.from(expected);
    return got.length === want.length && crypto.timingSafeEqual(got, want);
  }

  function reply(res, status, body) {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(body === undefined ? '' : JSON.stringify(body));
  }

  function readJson(req) {
    return new Promise((resolve) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        // FreeRADIUS posts form fields; JSON is accepted too.
        if (/application\/x-www-form-urlencoded/i.test(req.headers['content-type'] ?? '')) {
          return resolve(Object.fromEntries(new URLSearchParams(text)));
        }
        try {
          resolve(JSON.parse(text || '{}'));
        } catch {
          resolve({});
        }
      });
    });
  }

  function who(body) {
    return {
      email: normalizeUsername(attr(body, 'User-Name'), cfg.defaultDomain),
      mac: attr(body, 'Calling-Station-Id') || null,
      ap: attr(body, 'Called-Station-Id') || null,
    };
  }

  async function authorize(res, body) {
    const { email, mac } = who(body);
    let decision;
    try {
      decision = await access.check(email);
    } catch (err) {
      // 5xx makes FreeRADIUS fall back to radius.fallbackVlan (or refuse if none is set).
      log('directory_error', { email, error: err.message });
      return reply(res, 503, { error: 'directory unavailable' });
    }
    if (!decision.allow) {
      refused.set(email, true, 60_000);
      log('denied', { email, mac, reason: decision.reason, orgUnit: decision.orgUnitPath });
      // FreeRADIUS expands %{…} in reply values, so a rule message must not contain %.
      const message = (decision.rule?.message ?? "This account can't use the school WiFi.").replace(/%/g, ' percent');
      return reply(res, 401, { 'reply:Reply-Message': message });
    }
    const out = { 'reply:Session-Timeout': cfg.sessionTimeout };
    if (decision.vlanId) {
      out['reply:Tunnel-Type'] = 'VLAN';
      out['reply:Tunnel-Medium-Type'] = 'IEEE-802';
      out['reply:Tunnel-Private-Group-Id'] = String(decision.vlanId);
    }
    return reply(res, 200, out);
  }

  // A Hotspot (WISPr) Access-Request from the vSZ, in one of two forms:
  //  - a sign-in from the portal page: User-Name is the email, User-Password the
  //    one-time ticket the portal issued after the school password checked out
  //  - a device reconnecting (MAC authentication on the WLAN): User-Name is its MAC
  // Either way the person's rule and the network's VLAN are checked again here.
  const refuse = (res, message) => reply(res, 401, { 'reply:Reply-Message': String(message).replace(/%/g, ' percent') });
  const noSsidWarned = new TtlMap();

  async function portal(res, body) {
    const user = String(attr(body, 'User-Name') ?? '').trim();
    const pass = String(attr(body, 'User-Password') ?? '');
    const mac = attr(body, 'Calling-Station-Id') || null;
    const ap = attr(body, 'Called-Station-Id') || null;
    const ssidSeen = ssidFromCalledStation(ap);
    const remembering = isMac(user) && (!mac || normalizeMac(user) === normalizeMac(mac));

    let email;
    let ssid = ssidSeen;
    let device = null;
    if (remembering) {
      device = db.portalDevice(mac ?? user);
      if (!device) return refuse(res, 'Sign in on the page that opens.'); // a new device: nothing to log
      if (!ssid) {
        // Without the SSID a student's remembered phone could get on to the staff network.
        if (!noSsidWarned.get('x')) log('portal_ssid_error', { error: 'the vSZ sent no SSID in Called-Station-Id, so remembered devices must sign in again (see the README)' });
        noSsidWarned.set('x', true, 3600_000);
        return refuse(res, 'Sign in on the page that opens.');
      }
      email = device.email;
    } else {
      email = normalizeUsername(user, cfg.defaultDomain);
      const ticket = tickets?.redeem(email, pass);
      if (!ticket) {
        log('denied', { email, mac, reason: 'not signed in on the portal (unknown or expired one-time password)' });
        return refuse(res, 'Sign in on the page that opens.');
      }
      ssid ??= ticket.ssid;
    }

    let decision;
    try {
      decision = await access.check(email);
    } catch (err) {
      log('directory_error', { email, error: err.message });
      return reply(res, 503, { error: 'directory unavailable' });
    }
    if (!decision.allow) {
      // Someone blocked, suspended or no longer in a rule loses their remembered devices.
      if (device) db.forgetDevices(email);
      log('denied', { email, mac, reason: decision.reason, orgUnit: decision.orgUnitPath });
      return refuse(res, decision.rule?.message ?? "This account can't use the school WiFi.");
    }
    const net = checkNetwork(config.portal.networks, decision, ssid);
    if (!net.ok) {
      log('denied', { email, mac, reason: net.reason, orgUnit: decision.orgUnitPath });
      return refuse(res, net.message);
    }

    const who = decision.email ?? email;
    if (device) db.touchDevice(mac ?? user);
    else if (config.portal.rememberDays > 0 && mac) db.rememberDevice({ mac, email: who, ssid: net.ssid }, config.portal.rememberDays);
    status.lastAccept = Date.now();
    const first = db.recordLogin({ email: who, mac, vlanId: net.vlanId, rule: decision.rule?.name ?? null, ap });
    if (first) log('signed_in', { email: who, mac, rule: decision.rule?.name, vlanId: net.vlanId, ssid: net.ssid, how: device ? 'remembered device' : 'sign-in page', orgUnit: decision.orgUnitPath });
    return reply(res, 200, { 'reply:Session-Timeout': cfg.sessionTimeout, 'reply:User-Name': who });
  }

  async function postAuth(res, body, result) {
    const { email, mac, ap } = who(body);
    status[result === 'accept' ? 'lastAccept' : 'lastReject'] = Date.now();
    if (result === 'accept') {
      const vlan = attr(body, 'Tunnel-Private-Group-Id');
      const decision = await access.check(email).catch(() => null);
      const first = db.recordLogin({ email, mac, vlanId: vlan ? Number(vlan) : decision?.vlanId ?? null, rule: decision?.rule?.name ?? null, ap });
      // One activity line per device per day keeps Activity readable; every login is counted.
      if (first) log('signed_in', { email, mac, rule: decision?.rule?.name, vlanId: decision?.vlanId, orgUnit: decision?.orgUnitPath });
    } else if (!refused.get(email)) {
      log('denied', { email, mac, reason: 'wrong password, or not a school Google account' });
    }
    return reply(res, 204);
  }

  // Whose usage this is: the login name the vSZ reports (set from the Access-Accept), or
  // for an "anonymous" outer identity, whoever last logged in from that device. Guest
  // keys on the guest SSID report the key's vSZ name ("guest#Mrs_Botha#it@…"), counted
  // as "guest: Mrs Botha (it@…)" whichever form the key was made with.
  function accountFor(body) {
    const raw = String(attr(body, 'User-Name') ?? '').trim();
    const mac = attr(body, 'Calling-Station-Id') || null;
    const guest = guestFromVszName(raw);
    if (guest) return guestDisplayName(guest);
    // A remembered device's session may be reported under its MAC.
    if (isMac(raw)) return db.portalDevice(raw)?.email ?? db.lastLoginByMac(raw) ?? `unknown device ${mac ?? raw}`;
    const email = normalizeUsername(raw, cfg.defaultDomain);
    if (email && !/^anonymous@/.test(email)) return email;
    return (mac && db.lastLoginByMac(mac)) || `unknown device ${mac ?? ''}`.trim();
  }

  function accounting(res, body) {
    status.lastAccounting = Date.now();
    const who = accountFor(body);
    // RADIUS counters are 32-bit; Gigawords counts how often they wrapped. From the
    // controller's side, input is what the device uploaded and output what it downloaded.
    const up = int(attr(body, 'Acct-Input-Gigawords')) * 2 ** 32 + int(attr(body, 'Acct-Input-Octets'));
    const down = int(attr(body, 'Acct-Output-Gigawords')) * 2 ** 32 + int(attr(body, 'Acct-Output-Octets'));
    const today = db.recordAccounting({
      status: attr(body, 'Acct-Status-Type') || 'Interim-Update',
      sessionId: attr(body, 'Acct-Session-Id') || null,
      who,
      mac: attr(body, 'Calling-Station-Id') || null,
      ip: attr(body, 'Framed-IP-Address') || null,
      ap: attr(body, 'Called-Station-Id') || null,
      nas: attr(body, 'NAS-Identifier') || attr(body, 'NAS-IP-Address') || null,
      down,
      up,
      seconds: attr(body, 'Acct-Session-Time') ? int(attr(body, 'Acct-Session-Time')) : null,
      cause: attr(body, 'Acct-Terminate-Cause') || null,
    });
    const limitGb = settings?.current().usageAlertGb;
    if (today && limitGb && today.total >= limitGb * GB && who.includes('@') && !db.hadEventToday('usage_high', who)) {
      log('usage_high', { email: who, gb: Math.round((today.total / GB) * 10) / 10, limitGb });
    }
    return reply(res, 204);
  }

  async function handle(req, res, url) {
    if (req.method !== 'POST' || !allowed(req)) return reply(res, 404, { error: 'not found' });
    const body = await readJson(req);
    status.lastRequest = Date.now();
    if (url.pathname === '/radius/portal') return portal(res, body);
    if (url.pathname === '/radius/authorize') return authorize(res, body);
    if (url.pathname === '/radius/post-auth') return postAuth(res, body, url.searchParams.get('result'));
    if (url.pathname === '/radius/accounting') return accounting(res, body);
    return reply(res, 404, { error: 'not found' });
  }

  return { handle, status: () => status, close: () => (refused.close(), noSsidWarned.close()) };
}
