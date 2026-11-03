// Data used per person, from the vSZ's RADIUS accounting (forwarded by FreeRADIUS).
import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, test } from 'node:test';
import { createAlerts } from '../src/alerts.js';
import { dayOf, openDb } from '../src/db.js';
import { startPlatform } from './helpers.js';

const GB = 1024 ** 3;
let h;
let admin;
const auth = `Basic ${Buffer.from('radius:test-token-0123456789abcdef').toString('base64')}`;

// What FreeRADIUS posts for one accounting packet.
async function acct(fields) {
  const res = await fetch(`http://127.0.0.1:${h.server.address().port}/radius/accounting`, {
    method: 'POST',
    headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ 'NAS-Identifier': 'vsz', ...fields }),
  });
  return res.status;
}

before(async () => {
  h = await startPlatform();
  h.users.set('t.smith@school.org', { orgUnitPath: '/Staff', suspended: false });
  admin = await h.loginAdmin();
});
after(() => h.close());

describe('accounting', () => {
  test('a session is counted from start to stop, and only the growth is added', async () => {
    const base = { 'User-Name': 't.smith@school.org', 'Calling-Station-Id': 'AA-BB-CC-00-00-01', 'Acct-Session-Id': 's1', 'Framed-IP-Address': '10.20.1.5' };
    assert.equal(await acct({ ...base, 'Acct-Status-Type': 'Start' }), 204);
    assert.equal(h.db.onlineNow().length, 1);
    await acct({ ...base, 'Acct-Status-Type': 'Interim-Update', 'Acct-Output-Octets': '300000000', 'Acct-Input-Octets': '20000000', 'Acct-Session-Time': '600' });
    await acct({ ...base, 'Acct-Status-Type': 'Interim-Update', 'Acct-Output-Octets': '500000000', 'Acct-Input-Octets': '50000000', 'Acct-Session-Time': '1200' });
    await acct({ ...base, 'Acct-Status-Type': 'Stop', 'Acct-Output-Octets': '600000000', 'Acct-Input-Octets': '60000000', 'Acct-Terminate-Cause': 'User-Request' });
    const today = h.db.usageOn('t.smith@school.org', dayOf(Date.now()));
    assert.equal(today.down, 600_000_000);
    assert.equal(today.up, 60_000_000);
    assert.equal(h.db.onlineNow().length, 0);
    const [s] = h.db.personUsage('t.smith@school.org', dayOf(Date.now())).sessions;
    assert.equal(s.ip, '10.20.1.5');
    assert.equal(s.cause, 'User-Request');
  });

  test('gigawords count sessions bigger than 4 GB', async () => {
    await acct({ 'User-Name': 'big@school.org', 'Calling-Station-Id': 'AA-BB-CC-00-00-02', 'Acct-Session-Id': 's2', 'Acct-Status-Type': 'Interim-Update', 'Acct-Output-Gigawords': '2', 'Acct-Output-Octets': '5' });
    assert.equal(h.db.usageOn('big@school.org', dayOf(Date.now())).down, 2 * 2 ** 32 + 5);
  });

  test('an anonymous outer identity is matched to whoever logged in from the device', async () => {
    h.db.recordLogin({ email: 'pupil@school.org', mac: 'AA-BB-CC-00-00-03', vlanId: 30 });
    await acct({ 'User-Name': 'anonymous@school.org', 'Calling-Station-Id': 'AA-BB-CC-00-00-03', 'Acct-Session-Id': 's3', 'Acct-Status-Type': 'Interim-Update', 'Acct-Output-Octets': '1000' });
    assert.equal(h.db.usageOn('pupil@school.org', dayOf(Date.now())).down, 1000);
  });

  test('guest keys on the guest SSID are counted under the key name', async () => {
    await acct({ 'User-Name': 'guest: Mrs Botha (it@school.org)', 'Calling-Station-Id': 'AA-BB-CC-00-00-04', 'Acct-Session-Id': 'g1', 'Acct-Status-Type': 'Interim-Update', 'Acct-Output-Octets': '2048' });
    assert.equal(h.db.usageOn('guest: Mrs Botha (it@school.org)', dayOf(Date.now())).down, 2048);
  });

  test('a controller restart closes its open sessions', async () => {
    await acct({ 'User-Name': 't.smith@school.org', 'Calling-Station-Id': 'AA-BB-CC-00-00-05', 'Acct-Session-Id': 's5', 'Acct-Status-Type': 'Start' });
    assert.ok(h.db.onlineNow().some((s) => s.mac === 'aa:bb:cc:00:00:05'));
    await acct({ 'Acct-Status-Type': 'Accounting-On' });
    assert.ok(!h.db.onlineNow().some((s) => s.mac === 'aa:bb:cc:00:00:05'));
  });
});

describe('daily totals', () => {
  test('usage is split across days at the time of each report, and counter resets count from zero', () => {
    const db = openDb(':memory:');
    const evening = new Date(2026, 10, 3, 23, 50).getTime();
    const morning = new Date(2026, 10, 4, 0, 10).getTime();
    const r = { status: 'Interim-Update', sessionId: 'x', who: 'a@school.org', mac: 'aa:aa:aa:aa:aa:aa', nas: 'vsz' };
    db.recordAccounting({ ...r, down: 100, up: 10 }, evening);
    db.recordAccounting({ ...r, down: 250, up: 30 }, morning);
    db.recordAccounting({ ...r, down: 40, up: 5 }, morning + 60_000);
    assert.deepEqual(db.usageOn('a@school.org', '2026-11-03'), { down: 100, up: 10, total: 110 });
    assert.deepEqual(db.usageOn('a@school.org', '2026-11-04'), { down: 150 + 40, up: 20 + 5, total: 215 });
    db.close();
  });
});

describe('dashboard and alerts', () => {
  beforeEach(() => h.settings.update({ usageAlertGb: null }));

  test('the Usage API reports totals, top users, VLANs and who is online', async () => {
    h.db.recordLogin({ email: 't.smith@school.org', mac: 'AA-BB-CC-00-00-01', vlanId: 20 });
    await acct({ 'User-Name': 't.smith@school.org', 'Calling-Station-Id': 'AA-BB-CC-00-00-09', 'Acct-Session-Id': 's9', 'Acct-Status-Type': 'Start' });
    const r = await h.req('/admin/api/usage?period=week', { cookie: admin.cookie });
    assert.equal(r.json.period, 'week');
    assert.equal(r.json.top[0].who, 'big@school.org');
    assert.ok(r.json.totals.down > 2 * 2 ** 32);
    assert.ok(r.json.byVlan.some((v) => v.vlan_id === 20));
    assert.ok(r.json.online.some((o) => o.mac === 'aa:bb:cc:00:00:09'));
    const p = await h.req('/admin/api/people/t.smith%40school.org', { cookie: admin.cookie });
    assert.equal(p.json.usage.daily[0].down, 600_000_000);
    const csv = await h.req('/admin/api/export/usage.csv', { cookie: admin.cookie });
    assert.match(csv.text, /^day,who,mac,bytes_down,bytes_up/);
  });

  test('passing the daily alert level is recorded once per person per day', async () => {
    const r = await h.api(admin, '/settings', { usageAlertGb: 1 });
    assert.equal(r.res.status, 200);
    const base = { 'User-Name': 'heavy@school.org', 'Calling-Station-Id': 'AA-BB-CC-00-00-10', 'Acct-Session-Id': 'h1', 'Acct-Status-Type': 'Interim-Update' };
    await acct({ ...base, 'Acct-Output-Octets': String(0.5 * GB) });
    assert.equal(h.db.events({ category: 'usage' }).length, 0);
    await acct({ ...base, 'Acct-Output-Octets': String(1.2 * GB) });
    await acct({ ...base, 'Acct-Output-Octets': String(1.5 * GB) });
    const alerts = h.db.events({ category: 'usage' });
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].email, 'heavy@school.org');
    assert.equal(alerts[0].detail.limitGb, 1);
    assert.equal((await h.api(admin, '/settings', { usageAlertGb: -3 })).res.status, 422);
  });

  test('the alert email names the person and the amount', async () => {
    const sent = [];
    const alerts = createAlerts({ mailer: { send: async (m) => sent.push(m) }, to: ['it@school.org'], publicUrl: 'https://wifi.test', log: () => {} });
    alerts.onEvent('usage_high', { email: 'heavy@school.org', gb: 5.2, limitGb: 5 });
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(sent[0].subject, '[WiFi] heavy@school.org used 5.2 GB today');
  });
});
