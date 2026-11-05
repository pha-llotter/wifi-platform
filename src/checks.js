import fs from 'node:fs';
import tls from 'node:tls';

// "Check connections": tries each outside service the platform depends on and says
// in plain words what works and what doesn't. Used by the Settings page and by
// `npm run check` on the server.

// --- A minimal LDAP search over TLS, enough to prove Google accepts the client certificate.

function berLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag, content) => Buffer.concat([Buffer.from([tag]), berLength(content.length), content]);
const str = (s, tag = 0x04) => tlv(tag, Buffer.from(s, 'utf8'));
const small = (n, tag = 0x02) => tlv(tag, Buffer.from([n])); // 0..127 is all this needs

/**
 * A bind followed by a search for one mail, as FreeRADIUS does it: with the LDAP client's
 * access credentials when they're set, otherwise anonymous (the certificate alone). Some
 * Workspace tenants let a certificate-only client see the OUs but no users.
 */
export function ldapSearchRequest(baseDn, email, { identity = '', password = '' } = {}) {
  const bind = tlv(0x60, Buffer.concat([small(3), str(identity ?? ''), str(password ?? '', 0x80)]));
  const filter = tlv(0xa3, Buffer.concat([str('mail'), str(email)])); // equalityMatch
  const search = tlv(0x63, Buffer.concat([
    str(baseDn), small(2, 0x0a), small(0, 0x0a), small(1), small(10), tlv(0x01, Buffer.from([0])),
    filter, tlv(0x30, str('mail')),
  ]));
  return Buffer.concat([tlv(0x30, Buffer.concat([small(1), bind])), tlv(0x30, Buffer.concat([small(2), search]))]);
}

/** Reads one TLV at `at`; null if the buffer doesn't hold all of it yet. */
function readTlv(buf, at) {
  if (at + 2 > buf.length) return null;
  let len = buf[at + 1];
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (start + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i];
    start += n;
  }
  if (start + len > buf.length) return null;
  return { tag: buf[at], start, end: start + len };
}

const LDAP_RESULTS = { 0: 'success', 32: 'no such object', 49: 'invalid credentials', 50: 'insufficient access rights', 53: 'unwilling to perform' };

/** The answer to a search: { found } or { code, message }, or null while incomplete. */
export function parseLdapReply(buf) {
  for (let at = 0; ; ) {
    const msg = readTlv(buf, at);
    if (!msg) return null;
    const id = readTlv(buf, msg.start);
    const op = id && readTlv(buf, id.end);
    if (!op) return { code: -1, message: 'unreadable reply' };
    if (op.tag === 0x64) return { found: true };
    // BindResponse, SearchResultDone, or a notice of disconnection: all start with a result.
    if (op.tag === 0x61 || op.tag === 0x65 || op.tag === 0x78) {
      const code = readTlv(buf, op.start);
      const value = code ? buf[code.end - 1] : -1;
      const dn = code && readTlv(buf, code.end);
      const text = dn && readTlv(buf, dn.end);
      const message = text ? buf.subarray(text.start, text.end).toString('utf8') : '';
      if (value !== 0) return { code: value, message: message || LDAP_RESULTS[value] || `result ${value}` };
      if (op.tag !== 0x61) return { found: false };
    }
    at = msg.end;
  }
}

export function ldapSearch({ host, port = 636, cert, key, baseDn, email, identity = '', password = '', timeoutMs = 10_000, tlsOptions = {} }) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername: host, cert, key, ...tlsOptions });
    let buf = Buffer.alloc(0);
    const done = (fn, value) => {
      clearTimeout(timer);
      socket.destroy();
      fn(value);
    };
    const timer = setTimeout(() => done(reject, new Error(`no answer from ${host}:${port} within ${timeoutMs / 1000}s`)), timeoutMs);
    socket.once('secureConnect', () => socket.write(ldapSearchRequest(baseDn, email, { identity, password })));
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const reply = parseLdapReply(buf);
      if (reply) done(resolve, reply);
    });
    socket.once('error', (err) => done(reject, err));
    socket.once('end', () => done(reject, new Error('the server closed the connection (is the client certificate accepted?)')));
  });
}

// --- The checks.

export function createChecks({ config, directory, mailer, vsz, drive = null, radiusStatus = () => null, ldap = ldapSearch }) {
  const adminEmail = config.google.directory?.adminEmail;
  const domain = config.radius.defaultDomain;
  const ldapConf = {
    host: 'ldap.google.com',
    port: 636,
    clientCert: '/etc/wifi-portal/google-ldap/ldap-client.crt',
    clientKey: '/etc/wifi-portal/google-ldap/ldap-client.key',
    baseDn: (domain ?? '').split('.').map((p) => `dc=${p}`).join(','),
    ...config.google.ldap,
  };

  const step = async (name, fn) => {
    try {
      return { name, ok: true, detail: await fn() };
    } catch (err) {
      return { name, ok: false, detail: err.message };
    }
  };
  const skipped = (name, detail) => ({ name, ok: null, detail });

  async function run({ email = true } = {}) {
    const results = [];

    results.push(directory
      ? await step('Google directory (OU lookups)', async () => {
          const user = await directory.getUser(adminEmail);
          if (!user) throw new Error(`${adminEmail} was not found`);
          return `found ${user.email} in ${user.orgUnitPath}`;
        })
      : skipped('Google directory (OU lookups)', 'not set up (google.directory)'));

    const lookup = adminEmail ?? config.admin.emails[0];
    results.push(await step('Google Secure LDAP (passwords)', async () => {
      let cert, key;
      try {
        cert = fs.readFileSync(ldapConf.clientCert);
        key = fs.readFileSync(ldapConf.clientKey);
      } catch (err) {
        throw new Error(`can't read the LDAP client certificate: ${err.message}`);
      }
      const withCredentials = Boolean(ldapConf.identity);
      const reply = await ldap({ host: ldapConf.host, port: ldapConf.port, cert, key, baseDn: ldapConf.baseDn, email: lookup, identity: ldapConf.identity, password: ldapConf.password });
      if (reply.found) return `the certificate${withCredentials ? ' and access credentials are' : ' is'} accepted and ${lookup} can be looked up`;
      if (reply.found === false) {
        throw new Error(`the certificate is accepted but ${lookup} wasn't found under ${ldapConf.baseDn}: ` + (withCredentials
          ? 'check the LDAP client\'s "Access permissions" (read user information, entire domain)'
          : 'the LDAP client probably needs access credentials as well (Admin console → the LDAP client → Access credentials → Generate). Put them in google.ldap.identity and password in config.json, and LDAP_IDENTITY and LDAP_PASSWORD in radius.env'));
      }
      if (reply.code === 49) throw new Error('Google refused the access credentials (invalid credentials): check google.ldap.identity and password, and that they match LDAP_IDENTITY and LDAP_PASSWORD in radius.env');
      const hint = reply.code === 32
        ? ` (is ${ldapConf.baseDn} right, and may the LDAP client read users? Set google.ldap.baseDn if the base differs)`
        : reply.code === 50 ? ' (the LDAP client in the Admin console needs "Read user information")' : '';
      throw new Error(`Google refused the search: ${reply.message}${hint}`);
    }));

    if (!mailer || !config.alerts.to.length) results.push(skipped('Alert emails (Gmail API)', 'not set up (alerts.from and alerts.to)'));
    else if (!email) results.push(skipped('Alert emails (Gmail API)', 'not tested'));
    else results.push(await step('Alert emails (Gmail API)', async () => {
      await mailer.send({
        to: config.alerts.to,
        subject: `${config.branding.name}: test alert`,
        text: `This is a test from "Check connections". If it arrived, alert emails work.\n\n${config.publicUrl}/admin\n`,
      });
      return `a test email was sent to ${config.alerts.to.join(', ')}: check that it arrived`;
    }));

    results.push(drive
      ? await step('Off-site backups (Google Drive)', () => drive.test())
      : skipped('Off-site backups (Google Drive)', 'not set up (backup.drive): backups stay on this server only'));

    results.push(await step('vSZ API (guest keys)', async () => {
      const keys = await vsz.listKeys();
      return `${config.dpsk.host}: signed in, ${keys.length} key${keys.length === 1 ? '' : 's'} on ${config.dpsk.ssid} (${vsz.health.security})`;
    }));

    const r = radiusStatus();
    if (!r?.lastRequest) results.push({ name: 'FreeRADIUS', ok: null, detail: 'no login has reached the platform yet: try `npm run test:login` on the server, or join the WiFi' });
    else results.push({ name: 'FreeRADIUS', ok: true, detail: `last login request ${Math.round((Date.now() - r.lastRequest) / 60_000)} min ago` });

    return results;
  }

  return { run };
}
