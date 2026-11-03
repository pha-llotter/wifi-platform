// The HTTP API FreeRADIUS calls (rlm_rest) during each 802.1X login on the school SSID:
//   POST /radius/authorize               → 200 with the VLAN to put the device on, or 401 to refuse
//   POST /radius/post-auth?result=accept|reject  → recorded for the dashboard
//   POST /radius/accounting              → data used per session (start, updates, stop) for the Usage page
// FreeRADIUS checks the password itself, against Google Secure LDAP. Only FreeRADIUS
// may call this: it must come from an allowed address and carry the shared token.
import crypto from 'node:crypto';
import { normalizeUsername } from './access.js';
import { ipAllowed } from './admin.js';
import { TtlMap } from './store.js';

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

export function createRadiusApi({ config, db, access, settings, log }) {
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
  // keys on the guest SSID report the key's name, e.g. "guest: Mrs Botha (it@…)".
  function accountFor(body) {
    const raw = String(attr(body, 'User-Name') ?? '').trim();
    const mac = attr(body, 'Calling-Station-Id') || null;
    if (/^guest: /i.test(raw)) return raw;
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
    if (url.pathname === '/radius/authorize') return authorize(res, body);
    if (url.pathname === '/radius/post-auth') return postAuth(res, body, url.searchParams.get('result'));
    if (url.pathname === '/radius/accounting') return accounting(res, body);
    return reply(res, 404, { error: 'not found' });
  }

  return { handle, status: () => status, close: () => refused.close() };
}
