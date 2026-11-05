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
    dpsk: { host: 'vsz', protocol: 'http', username: 'u', password: 'p', zoneId: 'z', wlanId: 'w', ssid: 'Guest' },
    portal: { networks: { Nexus: 30, "Nexus Staff": 20 }, nbi: { host: "vsz", protocol: "http", password: "nbi" } },
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

  test('with access credentials the bind carries them, as FreeRADIUS sends LDAP_IDENTITY', () => {
    const req = ldapSearchRequest('dc=school,dc=org', 'a@school.org', { identity: 'SomeClient', password: 's3cret' });
    const bindAt = req.indexOf(0x60);
    assert.ok(bindAt > 0 && req.indexOf(Buffer.from('SomeClient')) > bindAt, 'the identity is in the bind');
    assert.ok(req.includes(Buffer.concat([Buffer.from([0x80, 6]), Buffer.from('s3cret')])), 'the password is a simple bind');
    assert.ok(req.indexOf(0x63, bindAt) > req.indexOf(Buffer.from('s3cret')), 'the search comes after the bind');
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

describe('off-site backups to Google Drive', () => {
  // A small stand-in for the Drive API: resumable uploads, list and trash.
  async function fakeDrive({ refuse = false } = {}) {
    const http = await import('node:http');
    const files = [];
    const calls = [];
    const server = http.createServer(async (req, res) => {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const body = Buffer.concat(chunks);
      const url = new URL(req.url, 'http://drive');
      calls.push(`${req.method} ${url.pathname} ${req.headers.authorization ?? ''}`);
      const send = (status, obj, headers = {}) => {
        res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
        res.end(JSON.stringify(obj));
      };
      if (refuse) return send(403, { error: { message: 'The user does not have sufficient permissions for this file.' } });
      if (req.method === 'POST' && url.pathname === '/upload/drive/v3/files') {
        const meta = JSON.parse(body);
        const id = `f${files.length + 1}`;
        files.push({ id, ...meta, trashed: false, createdTime: new Date(Date.now() + files.length).toISOString() });
        return send(200, {}, { Location: `http://127.0.0.1:${server.address().port}/session/${id}` });
      }
      if (req.method === 'PUT' && url.pathname.startsWith('/session/')) {
        const f = files.find((x) => x.id === url.pathname.split('/').pop());
        f.data = body;
        return send(200, { id: f.id });
      }
      if (req.method === 'GET' && url.pathname === '/drive/v3/files') {
        const list = files.filter((f) => !f.trashed && f.name.includes('wifi-portal-')).sort((a, b) => b.createdTime.localeCompare(a.createdTime));
        return send(200, { files: list.map(({ id, name, createdTime }) => ({ id, name, createdTime })) });
      }
      if (req.method === 'PATCH') {
        files.find((x) => x.id === url.pathname.split('/').pop()).trashed = JSON.parse(body).trashed;
        return send(200, {});
      }
      send(404, { error: { message: 'not found' } });
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    return { files, calls, api: `http://127.0.0.1:${server.address().port}`, close: () => server.close() };
  }

  test('each backup is uploaded gzipped as the chosen user, and only the newest are kept', async () => {
    const zlib = await import('node:zlib');
    const { createDriveBackup } = await import('../src/google.js');
    const fake = await fakeDrive();
    const scopes = [];
    const serviceAccount = { accessToken: async (scope, subject) => (scopes.push([scope, subject]), 'tok') };
    const drive = createDriveBackup({ serviceAccount, as: 'backups@school.org', folderId: 'folder-1', keep: 2, api: fake.api });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wp-drive-'));
    for (const day of [1, 2, 3]) {
      const file = path.join(dir, `wifi-portal-2026-01-0${day}.db`);
      fs.writeFileSync(file, `database ${day}`);
      const r = await drive.upload(file);
      assert.equal(r.name, `wifi-portal-2026-01-0${day}.db.gz`);
    }
    assert.deepEqual(scopes[0], ['https://www.googleapis.com/auth/drive.file', 'backups@school.org']);
    assert.ok(fake.files.every((f) => f.parents[0] === 'folder-1'));
    assert.equal(zlib.gunzipSync(fake.files[2].data).toString(), 'database 3');
    assert.deepEqual(fake.files.map((f) => f.trashed), [true, false, false], 'the oldest went to the trash');
    assert.equal(await drive.test(), 'backups@school.org can add files to the folder');
    assert.equal(fake.files.at(-1).name, 'connection-check.txt');
    assert.equal(fake.files.at(-1).trashed, true, 'the check file is trashed again');
    fake.close();
  });

  test("Drive's reason is passed on when it refuses", async () => {
    const { createDriveBackup } = await import('../src/google.js');
    const fake = await fakeDrive({ refuse: true });
    const drive = createDriveBackup({ serviceAccount: { accessToken: async () => 'tok' }, as: 'x@school.org', folderId: 'f', api: fake.api });
    await assert.rejects(drive.test(), /Drive upload failed: The user does not have sufficient permissions/);
    fake.close();
  });

  test('config: a folder is needed, and the uploader defaults to the alerts mailbox', () => {
    assert.throws(() => baseConfig({ backup: { drive: {} } }), /backup\.drive\.folderId/);
    const c = baseConfig({ backup: { drive: { folderId: 'abc' } } });
    assert.equal(c.backup.drive.as, 'alerts@school.org');
    assert.equal(c.backup.drive.keep, 30);
  });
});

describe('connection guide', () => {
  let h, a;
  before(async () => {
    h = await startPlatform();
    a = await h.loginAdmin();
  });
  after(() => h.close());

  test('admins get a printable guide filled in from the config; others get nothing', async () => {
    const r = await h.req('/admin/guide', { cookie: a.cookie });
    assert.equal(r.res.status, 200);
    assert.match(r.text, /Connecting to Nexus/);
    assert.match(r.text, /nothing to install/);
    assert.match(r.text, /<strong>portal\.test<\/strong>, with a padlock/);
    assert.match(r.text, /<strong>Nexus Staff<\/strong>: Staff/, 'each network lists the rules that use it');
    assert.match(r.text, /deleted automatically after <strong>90 days/);
    assert.match(r.text, /Guest/);
    assert.doesNotMatch((await h.req('/admin/guide')).text, /Connecting to/);
  });

  test('absurdly long usernames are refused before any rule runs', async () => {
    const d = await h.access.check(`${'a'.repeat(200)}@school.org`);
    assert.equal(d.allow, false);
    assert.equal(d.reason, 'username too long');
  });
});
