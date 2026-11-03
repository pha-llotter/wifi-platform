// The guest SSID (visitor keys), slips, exports, backups, alerts and
// certificate pinning for the vSZ API.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import { createAlerts } from '../src/alerts.js';
import { openDb } from '../src/db.js';
import { createVszClient } from '../src/vsz.js';
import { startPlatform } from './helpers.js';

let h;
let a;
before(async () => {
  h = await startPlatform();
  a = await h.loginAdmin();
});
after(() => h.close());

describe('guest keys', () => {
  test('an admin makes a guest key on the guest VLAN that ends on time', async () => {
    const r = await h.api(a, '/guests', { name: 'Mrs Botha', days: 3 });
    const row = h.db.getKeyRow(r.json.id);
    assert.equal(row.kind, 'guest');
    assert.equal(row.vlan_id, 50);
    assert.ok(row.expires > Date.now() + 2.9 * 86_400_000 && row.expires < Date.now() + 3.1 * 86_400_000);
    assert.equal(h.vsz.keys.get(r.json.id).userName, 'guest: Mrs Botha (it@school.org)');
    assert.match((await h.api(a, '/guests', { name: 'Too long', days: 30 })).json.problems[0], /from 1 to 7 days/);

    h.db.removeKey(row.id);
    h.db.addKey({ ...row, vlanId: row.vlan_id, createdBy: row.created_by, expires: Date.now() - 1 });
    assert.equal(await h.keys.expireGuests(), 1);
    assert.ok(!h.vsz.keys.has(row.id));
  });
});

describe('guest key tools', () => {
  test('guest keys stay on the guest VLAN through a sync and show in the list', async () => {
    const r = await h.api(a, '/guests', { name: 'Coach Peters', days: 2 });
    await h.keys.sync({ by: 'test' });
    assert.equal(h.db.getKeyRow(r.json.id).vlan_id, 50);
    assert.ok((await h.req('/admin/api/guests', { cookie: a.cookie })).json.some((k) => k.label === 'Coach Peters'));
  });

  test('reset frees a bound key and keeps the passphrase', async () => {
    const { json } = await h.api(a, '/guests', { name: 'Visiting teacher', days: 1 });
    const pass = h.vsz.keys.get(json.id).passphrase;
    h.vsz.bind(json.id, 'AA:AA:AA:AA:AA:01');
    await h.keys.sync({ by: 'test' });
    assert.equal(h.db.getKeyRow(json.id).mac, 'aa:aa:aa:aa:aa:01');
    const r = await h.api(a, `/keys/${json.id}/reset`);
    assert.notEqual(r.json.id, json.id);
    assert.equal(h.vsz.keys.get(r.json.id).passphrase, pass);
    assert.equal(h.vsz.keys.get(r.json.id).macAddress, null);
    assert.equal(h.db.getKeyRow(r.json.id).label, 'Visiting teacher');
    assert.equal(h.db.getKeyRow(r.json.id).kind, 'guest');
  });

  test('slips show the key and a QR code, to signed-in admins only', async () => {
    const [guest] = h.db.keysOfKind('guest');
    const slips = await h.req(`/admin/print?ids=${guest.id}`, { cookie: a.cookie });
    assert.match(slips.text, /class="slip"/);
    assert.match(slips.text, /<svg[^>]+aria-label="QR code to join PHA-Guest"/);
    assert.match(slips.text, /Works until/);
    assert.ok(slips.text.includes(h.vsz.keys.get(guest.id).passphrase));
    assert.doesNotMatch((await h.req(`/admin/print?ids=${guest.id}`)).text, /class="slip"/);
  });

  test('guest keys found on the vSZ can be adopted after a restore', async () => {
    const res = await fetch(`http://127.0.0.1:${h.config.dpsk.port}/wsg/api/public/v9_1/serviceTicket`, {
      method: 'POST',
      body: JSON.stringify({ username: h.vsz.config.username, password: h.vsz.config.password }),
    });
    const { serviceTicket } = await res.json();
    for (const userName of ['guest: Mr Dube (it@school.org)', 'made by hand']) {
      await fetch(`http://127.0.0.1:${h.config.dpsk.port}/wsg/api/public/v9_1/rkszones/zone-1/wlans/wlan-1/dpsk/batchGenUnbound?serviceTicket=${serviceTicket}`, {
        method: 'POST',
        body: JSON.stringify({ amount: 1, userName }),
      });
    }
    assert.deepEqual((await h.api(a, '/adopt')).json, { adopted: 1, skipped: 1 });
    const adopted = h.db.keysOfKind('guest').find((k) => k.label === 'Mr Dube');
    assert.ok(adopted.expires < Date.now() + 86_400_001);
  });

  test('the exports are CSV and defuse spreadsheet formulas', async () => {
    await h.api(a, '/guests', { name: '=HYPERLINK("x")', days: 1 });
    const keys = await h.req('/admin/api/export/keys.csv', { cookie: a.cookie });
    assert.match(keys.res.headers.get('content-type'), /text\/csv/);
    assert.ok(keys.text.includes(`"'=HYPERLINK(""x"")"`));
    h.db.recordLogin({ email: 'pupil@school.org', mac: 'aa:bb:cc:dd:ee:ff', vlanId: 30 });
    const logins = await h.req('/admin/api/export/logins.csv', { cookie: a.cookie });
    assert.match(logins.text, /^email,mac,vlan_id/);
    assert.match(logins.text, /pupil@school\.org,aa:bb:cc:dd:ee:ff,30/);
  });
});

describe('platform', () => {
  test('backups are consistent copies and old ones are pruned', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wifi-backup-'));
    const db = openDb(path.join(dir, 'live.db'));
    db.recordLogin({ email: 'a@school.org', mac: 'aa:aa:aa:aa:aa:aa' });
    for (let i = 0; i < 4; i++) db.backup(path.join(dir, 'backups'), 2, new Date(Date.UTC(2026, 0, 1 + i)));
    const files = fs.readdirSync(path.join(dir, 'backups')).sort();
    assert.deepEqual(files, ['wifi-portal-2026-01-03-00-00-00.db', 'wifi-portal-2026-01-04-00-00-00.db']);
    const copy = openDb(path.join(dir, 'backups', files[1]));
    assert.equal(copy.person('a@school.org').devices.length, 1);
    copy.close();
    db.close();
  });

  test('alerts email IT once an hour per kind of problem', async () => {
    const sent = [];
    const alerts = createAlerts({ mailer: { send: async (m) => sent.push(m) }, to: ['it@school.org'], publicUrl: 'https://wifi.test', log: () => {} });
    alerts.onEvent('directory_error', { error: 'quota exceeded' });
    alerts.onEvent('directory_error', { error: 'again' });
    alerts.onEvent('vsz_error', { error: 'connection refused' });
    await new Promise((r) => setTimeout(r, 10));
    assert.deepEqual(sent.map((m) => m.subject), ["[WiFi] The Google directory isn't answering", "[WiFi] The vSZ API isn't working"]);
  });
});

describe('certificate pinning for the vSZ API', () => {
  let server, port;
  const tlsOpts = {
    key: fs.readFileSync(new URL('./fixtures/vsz-test.key', import.meta.url)),
    cert: fs.readFileSync(new URL('./fixtures/vsz-test.crt', import.meta.url)),
  };
  before(async () => {
    server = https.createServer(tlsOpts, (req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(req.url.includes('serviceTicket') && req.method === 'POST' ? { serviceTicket: 'ST-1' } : { list: [], hasMore: false }));
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    port = server.address().port;
  });
  after(() => server.close());

  const client = (tlsFingerprint, tlsVerify = false) =>
    createVszClient({ host: '127.0.0.1', port, username: 'u', password: 'p', zoneId: 'z', wlanId: 'w', tlsFingerprint, tlsVerify });

  test('the pinned certificate is accepted', async () => {
    const c = client('63:DB:F0:2D:F7:56:07:07:40:9D:5B:A6:3B:E9:26:74:D0:D2:4B:BD:4C:3B:5B:9D:E9:8D:66:D1:D0:98:FC:D9');
    assert.equal(c.health.security, 'pinned');
    assert.deepEqual(await c.listKeys(), []);
  });

  test('any other certificate is refused before the password is sent', async () => {
    let gotRequest = false;
    server.once('request', () => (gotRequest = true));
    await assert.rejects(client('00'.repeat(32)).listKeys(), /doesn't match the pinned fingerprint/);
    assert.equal(gotRequest, false);
  });

  test('normal verification refuses a self-signed certificate', async () => {
    await assert.rejects(client(null, true).listKeys(), /self[- ]signed/i);
  });
});
