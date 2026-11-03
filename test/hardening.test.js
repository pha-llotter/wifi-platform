import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { createAccess } from '../src/access.js';
import { createChecks, ldapSearchRequest, parseLdapReply } from '../src/checks.js';
import { normalizeConfig } from '../src/config.js';
import { createLogger } from '../src/log.js';
import { TtlMap } from '../src/store.js';
import { startPlatform } from './helpers.js';

const baseConfig = (extra = {}) =>
  normalizeConfig({
    publicUrl: 'https://wifi.school.org',
    google: { clientId: 'cid', clientSecret: 'cs', allowedDomains: ['school.org'], directory: { enabled: true, serviceAccountKeyFile: 'x', adminEmail: 'a@school.org' } },
    radius: { apiToken: 'test-token-0123456789abcdef' },
    dpsk: { host: 'vsz', protocol: 'http', username: 'u', password: 'p', zoneId: 'z', wlanId: 'w', ssid: 'PHA-Guest' },
    admin: { emails: ['it@school.org'] },
    alerts: { from: 'alerts@school.org', to: ['it@school.org'] },
    ...extra,
  });

describe('connection check', () => {
  test('LDAP replies: an entry, nothing found, and a refusal with its message', () => {
    const entry = Buffer.from('300c020102640704000201002000', 'hex'); // msg 2, SearchResultEntry (empty)
    assert.deepEqual(parseLdapReply(entry), { found: true });
    const bindOk = Buffer.from('300c02010161070a010004000400', 'hex');
    const doneEmpty = Buffer.from('300c02010265070a010004000400', 'hex');
    assert.equal(parseLdapReply(bindOk), null, 'a successful bind alone is not an answer yet');
    assert.deepEqual(parseLdapReply(Buffer.concat([bindOk, doneEmpty])), { found: false });
    const refused = Buffer.from('301002010265 0b 0a0132 0400 0404 6e6f7065'.replace(/ /g, ''), 'hex');
    assert.deepEqual(parseLdapReply(refused), { code: 50, message: 'nope' });
    assert.equal(parseLdapReply(refused.subarray(0, 6)), null, 'waits for the rest of a message');
  });

  test('the request is an anonymous bind then a search for the mail address', () => {
    const req = ldapSearchRequest('dc=school,dc=org', 'a@school.org');
    assert.equal(req[0], 0x30);
    assert.ok(req.includes(Buffer.from('dc=school,dc=org')) && req.includes(Buffer.from('a@school.org')));
    assert.equal(req.indexOf(0x63) > req.indexOf(0x60), true);
  });

  test('each service is reported, with failures in plain words', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-check-'));
    fs.writeFileSync(path.join(dir, 'c.crt'), 'cert');
    fs.writeFileSync(path.join(dir, 'c.key'), 'key');
    const config = baseConfig({ google: { clientId: 'cid', clientSecret: 'cs', allowedDomains: ['school.org'], directory: { enabled: true, serviceAccountKeyFile: 'x', adminEmail: 'a@school.org' }, ldap: { clientCert: path.join(dir, 'c.crt'), clientKey: path.join(dir, 'c.key') } } });
    const sent = [];
    let ldapArgs;
    const checks = createChecks({
      config,
      directory: { getUser: async (e) => ({ email: e, orgUnitPath: '/IT' }) },
      mailer: { send: async (m) => sent.push(m) },
      vsz: { listKeys: async () => { throw new Error('vSZ said no'); }, health: { security: 'pinned' } },
      radiusStatus: () => ({ lastRequest: Date.now() - 120_000 }),
      ldap: async (o) => ((ldapArgs = o), { found: true }),
    });
    const results = await checks.run();
    const by = Object.fromEntries(results.map((r) => [r.name.split(' (')[0], r]));
    assert.equal(by['Google directory'].ok, true);
    assert.match(by['Google directory'].detail, /\/IT/);
    assert.equal(by['Google Secure LDAP'].ok, true);
    assert.equal(ldapArgs.baseDn, 'dc=school,dc=org');
    assert.equal(ldapArgs.cert.toString(), 'cert');
    assert.equal(by['Alert emails'].ok, true);
    assert.deepEqual(sent[0].to, ['it@school.org']);
    assert.equal(by['vSZ API'].ok, false);
    assert.match(by['vSZ API'].detail, /vSZ said no/);
    assert.match(by.FreeRADIUS.detail, /2 min ago/);
    assert.equal((await checks.run({ email: false })).find((r) => r.name.startsWith('Alert')).ok, null);
    assert.equal(sent.length, 1);
  });

  test('a missing LDAP certificate is named', async () => {
    const checks = createChecks({ config: baseConfig(), directory: null, mailer: null, vsz: { listKeys: async () => [], health: {} } });
    const ldap = (await checks.run()).find((r) => r.name.startsWith('Google Secure LDAP'));
    assert.equal(ldap.ok, false);
    assert.match(ldap.detail, /can't read the LDAP client certificate/);
  });

  describe('from the dashboard', () => {
    let h, a;
    before(async () => {
      h = await startPlatform();
      a = await h.loginAdmin();
    });
    after(() => h.close());

    test('print and exports refuse cross-site requests', async () => {
      const r = await fetch(`http://127.0.0.1:${h.server.address().port}/admin/api/export/logins.csv`, { headers: { cookie: a.cookie, 'sec-fetch-site': 'cross-site' } });
      assert.equal(r.status, 403);
      const ok = await fetch(`http://127.0.0.1:${h.server.address().port}/admin/api/export/logins.csv`, { headers: { cookie: a.cookie, 'sec-fetch-site': 'same-origin' } });
      assert.equal(ok.status, 200);
    });

    test('many started sign-ins do not get in the way of a real one', async () => {
      for (let i = 0; i < 30; i++) await h.req('/admin/login');
      assert.ok((await h.loginAdmin()).cookie, 'a real sign-in still works');
    });
  });
});

describe('hardening', () => {
  test('the vSZ password is only sent to a checked certificate', () => {
    assert.throws(() => baseConfig({ dpsk: { host: 'vsz', username: 'u', password: 'p', zoneId: 'z', wlanId: 'w', ssid: 'G' } }), /tlsFingerprint is required/);
    const fp = Array(32).fill('AB').join(':');
    assert.equal(baseConfig({ dpsk: { host: 'vsz', username: 'u', password: 'p', zoneId: 'z', wlanId: 'w', ssid: 'G', tlsFingerprint: fp } }).dpsk.tlsFingerprint, fp);
    assert.ok(baseConfig({ dpsk: { host: 'vsz', username: 'u', password: 'p', zoneId: 'z', wlanId: 'w', ssid: 'G', tlsVerify: true } }));
  });

  test('a capped map drops its oldest entries', () => {
    const m = new TtlMap({ max: 3 });
    for (const k of ['a', 'b', 'c', 'd']) m.set(k, k, 60_000);
    assert.equal(m.size, 3);
    assert.equal(m.get('a'), undefined);
    assert.equal(m.get('d'), 'd');
    m.close();
  });

  test('an alias is judged as the primary address, so a block still applies', async () => {
    const blocked = new Set(['t.smith@school.org']);
    const config = baseConfig({ policy: { rules: [{ name: 'All', vlanId: 20 }], default: null } });
    const { createSettings } = await import('../src/settings.js');
    const { openDb } = await import('../src/db.js');
    const db = openDb(':memory:');
    for (const e of blocked) db.block(e, 'test', 'it@school.org');
    const settings = createSettings({ config, db });
    const access = createAccess({ settings, directory: { getUser: async () => ({ email: 'T.Smith@school.org', orgUnitPath: '/Staff' }) } });
    const d = await access.check('tom@school.org');
    assert.equal(d.allow, false);
    assert.equal(d.reason, 'blocked by an admin');
    db.close();
  });

  test('the log file rotates and keeps a few old copies', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-log-'));
    const file = path.join(dir, 'wifi.jsonl');
    const write = process.stdout.write;
    process.stdout.write = () => true;
    try {
      const log = createLogger(file, { maxBytes: 300, keep: 2 });
      for (let i = 0; i < 40; i++) log('event', { i, pad: 'x'.repeat(40) });
      log.close();
    } finally {
      process.stdout.write = write;
    }
    const names = fs.readdirSync(dir).sort();
    assert.deepEqual(names, ['wifi.jsonl', 'wifi.jsonl.1', 'wifi.jsonl.2']);
    assert.ok(fs.statSync(path.join(dir, 'wifi.jsonl.1')).size <= 300);
  });
});
