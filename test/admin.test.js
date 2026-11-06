import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { ipAllowed } from '../src/admin.js';
import { openDb } from '../src/db.js';
import { startPlatform } from './helpers.js';

describe('admin dashboard', () => {
  let h;
  let session;
  before(async () => {
    h = await startPlatform();
    h.users.set('pupil@school.org', { orgUnitPath: '/Students', suspended: false });
    h.users.set('t.smith@school.org', { orgUnitPath: '/Staff', suspended: false });
    session = await h.loginAdmin();
  });
  after(() => h.close());

  test('the site root goes to the dashboard; there is no public website', async () => {
    const r = await h.req('/');
    assert.equal(r.res.status, 302);
    assert.equal(r.res.headers.get('location'), '/admin');
    assert.equal((await h.req('/my')).res.headers.get('location'), '/admin');
  });

  test('signed-out visitors get the sign-in page and no data', async () => {
    assert.match((await h.req('/admin')).text, /Sign in with Google/);
    assert.equal((await h.req('/admin/api/overview')).res.status, 401);
  });

  test('a school account that is not on the admin list is refused', async () => {
    const { done, cookie } = await h.loginAdmin('teacher@school.org');
    assert.equal(cookie, undefined);
    assert.match(done.text, /isn&#39;t an admin/);
  });

  test('changes need the CSRF token', async () => {
    const r = await h.req('/admin/api/settings', { method: 'POST', cookie: session.cookie, body: { retentionDays: 30 } });
    assert.equal(r.res.status, 403);
  });

  test('invalid rules are refused with a reason and nothing is saved', async () => {
    const r = await h.api(session, '/settings', { retentionDays: 30, policy: { rules: [{ name: 'Bad', email: '([' }] } });
    assert.equal(r.res.status, 422);
    assert.match(r.json.problems.join(), /not a valid regular expression/);
    assert.equal(h.settings.current().retentionDays, 90);
  });

  test('saved rules apply at the next login, without waiting for the cache', async () => {
    assert.equal((await h.access.check('pupil@school.org')).vlanId, 30);
    const r = await h.api(session, '/settings', { policy: { rules: [{ name: 'Students', orgUnit: '/Students', vlanId: 35 }], default: { vlanId: 30 } } });
    assert.equal(r.res.status, 200);
    assert.equal((await h.access.check('pupil@school.org')).vlanId, 35);
    assert.ok(h.db.events({ category: 'admin' }).some((e) => e.detail.action === 'changed settings'));
  });

  test('blocking refuses the next login and shows in the list', async () => {
    assert.equal((await h.access.check('t.smith@school.org')).allow, true);
    const r = await h.api(session, '/people/t.smith%40school.org/block', { reason: 'Left the school' });
    assert.equal(r.json.blocked.reason, 'Left the school');
    assert.equal((await h.access.check('t.smith@school.org')).allow, false);
    const people = await h.req('/admin/api/people', { cookie: session.cookie });
    assert.equal(people.json.blocked[0].email, 't.smith@school.org');
    await h.api(session, '/people/t.smith%40school.org/unblock');
    assert.equal((await h.access.check('t.smith@school.org')).allow, true);
  });

  test('the overview and person pages show who logged in from which device', async () => {
    h.db.recordLogin({ email: 'pupil@school.org', mac: 'AA-BB-CC-00-00-07', vlanId: 35, rule: 'Students' });
    const o = await h.req('/admin/api/overview', { cookie: session.cookie });
    assert.equal(o.json.today.people, 1);
    assert.equal(o.json.recentLogins[0].mac, 'aa:bb:cc:00:00:07');
    const p = await h.req('/admin/api/people/pupil%40school.org', { cookie: session.cookie });
    assert.equal(p.json.devices[0].vlan_id, 35);
  });

  test('acknowledging problems clears them from the overview until a new one happens', async () => {
    const overview = async () => (await h.req('/admin/api/overview', { cookie: session.cookie })).json;
    h.db.record('portal_error', { email: 'pupil@school.org', error: 'the vSZ refused the login: Not found' });
    let o = await overview();
    assert.ok(o.errors24h >= 1);
    assert.equal(o.health.recentErrors[0].type, 'portal_error');

    await new Promise((r) => setTimeout(r, 5)); // the acknowledgement is later than the error
    const ack = await h.api(session, '/problems/acknowledge');
    assert.match(ack.json.by, /@/);
    o = await overview();
    assert.equal(o.errors24h, 0);
    assert.deepEqual(o.health.recentErrors, []);
    assert.equal(o.acknowledged.at, ack.json.at);
    assert.ok(h.db.events({ category: 'error' }).length >= 1, 'still in Activity');

    await new Promise((r) => setTimeout(r, 5));
    h.db.record('directory_error', { error: 'quota' });
    o = await overview();
    assert.equal(o.errors24h, 1);
    assert.equal(o.health.recentErrors[0].type, 'directory_error');
  });

  test('logout ends the admin session', async () => {
    const { cookie, csrf } = await h.loginAdmin();
    await h.req('/admin/api/logout', { method: 'POST', cookie, csrf, body: {} });
    assert.equal((await h.req('/admin/api/me', { cookie })).res.status, 401);
  });
});

describe('admin network restriction', () => {
  test('the dashboard refuses addresses outside admin.allowFrom', async () => {
    const h = await startPlatform({ admin: { emails: ['it@school.org'], allowFrom: ['10.0.0.0/8'] } });
    assert.equal((await h.req('/admin')).res.status, 403);
    h.close();
  });

  test('CIDR matching', () => {
    assert.equal(ipAllowed('10.1.2.3', ['10.0.0.0/8']), true);
    assert.equal(ipAllowed('11.1.2.3', ['10.0.0.0/8']), false);
    assert.equal(ipAllowed('203.0.113.7', ['203.0.113.7']), true);
    assert.equal(ipAllowed('192.168.1.200', ['192.168.1.128/25']), true);
    assert.equal(ipAllowed('anything', []), true);
  });
});

describe('records', () => {
  test('old events and device records are purged', () => {
    const db = openDb(':memory:');
    const old = Date.now() - 10 * 86_400_000;
    db.record('signed_in', { email: 'a@school.org' }, old);
    db.recordLogin({ email: 'a@school.org', mac: 'aa:aa:aa:aa:aa:aa' }, old);
    assert.deepEqual(db.purge(7), { events: 1, logins: 1, sessions: 0, usage: 0 });
    db.close();
  });
});
