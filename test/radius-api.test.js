// The API FreeRADIUS calls during a school SSID login: who may connect, on which VLAN,
// and recording each outcome. (dev/radius-e2e runs the same through real FreeRADIUS.)
import assert from 'node:assert/strict';
import http from 'node:http';
import { after, before, beforeEach, describe, test } from 'node:test';
import { createAccess, normalizeUsername } from '../src/access.js';
import { normalizeConfig } from '../src/config.js';
import { openDb } from '../src/db.js';
import { createRadiusApi } from '../src/radius-api.js';
import { createSettings } from '../src/settings.js';

const TOKEN = 'unit-token-0123456789abcdef';
const auth = `Basic ${Buffer.from(`radius:${TOKEN}`).toString('base64')}`;
const users = new Map();
let directoryDown = false;
let h;

before(async () => {
  const config = normalizeConfig({
    publicUrl: 'http://portal.test',
    google: { clientId: 'cid', clientSecret: 'cs', allowedDomains: ['school.org'], directory: { enabled: true, serviceAccountKeyFile: 'x', adminEmail: 'a@school.org' } },
    radius: { apiToken: TOKEN, sessionTimeout: 3600 },
    dpsk: { host: 'vsz', protocol: 'http', username: 'u', password: 'p', zoneId: 'z', wlanId: 'w', ssid: 'PHA-Guest' },
    policy: {
      rules: [
        { name: 'Exam rooms', email: '^exam\\.', deny: true, message: 'Exam accounts stay offline.' },
        { name: 'Staff', orgUnit: '/Staff', vlanId: 20 },
        { name: 'Students', orgUnit: '/Students', vlanId: 30 },
      ],
      default: null,
    },
    admin: { emails: ['it@school.org'] },
  });
  h = { lookups: 0, events: [] };
  h.db = openDb(':memory:');
  h.settings = createSettings({ config, db: h.db });
  const directory = {
    async getUser(email) {
      h.lookups++;
      if (directoryDown) throw new Error('directory unavailable');
      return users.get(email) ?? null;
    },
  };
  h.access = createAccess({ settings: h.settings, directory });
  const log = (event, data) => {
    h.events.push({ event, ...data });
    h.db.record(event, data);
  };
  h.api = createRadiusApi({ config, db: h.db, access: h.access, log });
  h.server = http.createServer((req, res) => h.api.handle(req, res, new URL(req.url, 'http://x')));
  await new Promise((r) => h.server.listen(0, '127.0.0.1', r));
  h.base = `http://127.0.0.1:${h.server.address().port}`;
  // What FreeRADIUS sends: form fields, with HTTP basic auth.
  h.call = async (path, fields, headers = {}) => {
    const res = await fetch(h.base + path, {
      method: 'POST',
      headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(fields),
    });
    const text = await res.text();
    return { status: res.status, json: text ? JSON.parse(text) : null };
  };
});

after(() => {
  h.server.close();
  h.api.close();
  h.db.close();
});

beforeEach(() => {
  users.clear();
  users.set('t.smith@school.org', { orgUnitPath: '/Staff/Science', suspended: false });
  users.set('pupil@school.org', { orgUnitPath: '/Students/Grade 9', suspended: false });
  users.set('exam.room1@school.org', { orgUnitPath: '/Staff', suspended: false });
  users.set('left@school.org', { orgUnitPath: '/Staff', suspended: true });
  directoryDown = false;
  h.access.forget();
  h.events.length = 0;
});

describe('who may connect, and where', () => {
  test('staff get their VLAN and a session length', async () => {
    const r = await h.call('/radius/authorize', { 'User-Name': 't.smith@school.org', 'Calling-Station-Id': 'AA-BB-CC-DD-EE-01' });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json, {
      'reply:Session-Timeout': 3600,
      'reply:Tunnel-Type': 'VLAN',
      'reply:Tunnel-Medium-Type': 'IEEE-802',
      'reply:Tunnel-Private-Group-Id': '20',
    });
  });

  test('learners land on their own VLAN', async () => {
    const r = await h.call('/radius/authorize', { 'User-Name': 'pupil@school.org' });
    assert.equal(r.json['reply:Tunnel-Private-Group-Id'], '30');
  });

  test('bare usernames and DOMAIN\\user forms become the school email', () => {
    assert.equal(normalizeUsername('T.Smith', 'school.org'), 't.smith@school.org');
    assert.equal(normalizeUsername('PHAHS\\t.smith', 'school.org'), 't.smith@school.org');
    assert.equal(normalizeUsername('t.smith@school.org', 'school.org'), 't.smith@school.org');
  });

  test('refusals carry the reason to the dashboard and a message to the device', async () => {
    const exam = await h.call('/radius/authorize', { 'User-Name': 'exam.room1@school.org' });
    assert.equal(exam.status, 401);
    assert.equal(exam.json['reply:Reply-Message'], 'Exam accounts stay offline.');
    assert.equal((await h.call('/radius/authorize', { 'User-Name': 'left@school.org' })).status, 401);
    assert.equal((await h.call('/radius/authorize', { 'User-Name': 'nobody@school.org' })).status, 401);
    assert.equal((await h.call('/radius/authorize', { 'User-Name': 'someone@gmail.com' })).status, 401);
    const reasons = h.events.filter((e) => e.event === 'denied').map((e) => e.reason);
    assert.deepEqual(reasons, ['rule "Exam rooms"', 'account suspended or archived', 'not in the Google directory', "gmail.com isn't an allowed domain"]);
  });

  test('a block applies at the next login', async () => {
    assert.equal((await h.call('/radius/authorize', { 'User-Name': 'pupil@school.org' })).status, 200);
    h.db.block('pupil@school.org', 'test', 'it@school.org');
    h.access.forget('pupil@school.org');
    assert.equal((await h.call('/radius/authorize', { 'User-Name': 'pupil@school.org' })).status, 401);
    h.db.unblock('pupil@school.org');
  });

  test('when Google does not answer, FreeRADIUS gets a 5xx and uses its fallback', async () => {
    directoryDown = true;
    const r = await h.call('/radius/authorize', { 'User-Name': 't.smith@school.org' });
    assert.equal(r.status, 503);
    assert.ok(h.events.some((e) => e.event === 'directory_error'));
  });

  test('decisions are cached so roaming devices do not hammer the directory', async () => {
    const before = h.lookups;
    for (let i = 0; i < 5; i++) await h.call('/radius/authorize', { 'User-Name': 't.smith@school.org' });
    assert.equal(h.lookups - before, 1);
  });
});

describe('recording outcomes', () => {
  test('a successful login records the device, once per day in Activity', async () => {
    const fields = { 'User-Name': 't.smith@school.org', 'Calling-Station-Id': 'AA-BB-CC-DD-EE-01', 'Tunnel-Private-Group-Id': '20' };
    assert.equal((await h.call('/radius/post-auth?result=accept', fields)).status, 204);
    await h.call('/radius/post-auth?result=accept', fields);
    const devices = h.db.person('t.smith@school.org').devices;
    assert.equal(devices.length, 1);
    assert.equal(devices[0].mac, 'aa:bb:cc:dd:ee:01');
    assert.equal(devices[0].vlan_id, 20);
    assert.equal(devices[0].count, 2);
    assert.equal(h.events.filter((e) => e.event === 'signed_in').length, 1);
  });

  test('a wrong password is recorded, but a refusal the platform made is not counted twice', async () => {
    await h.call('/radius/post-auth?result=reject', { 'User-Name': 'typo@school.org' });
    assert.equal(h.events.at(-1).reason, 'wrong password, or not a school Google account');
    h.events.length = 0;
    await h.call('/radius/authorize', { 'User-Name': 'exam.room1@school.org' });
    await h.call('/radius/post-auth?result=reject', { 'User-Name': 'exam.room1@school.org' });
    assert.equal(h.events.filter((e) => e.event === 'denied').length, 1);
  });
});

describe('only FreeRADIUS may call it', () => {
  test('a wrong token, a public proxy hop or a GET all look like nothing is there', async () => {
    assert.equal((await h.call('/radius/authorize', { 'User-Name': 'x' }, { authorization: 'Basic d3Jvbmc6dG9rZW4=' })).status, 404);
    assert.equal((await h.call('/radius/authorize', { 'User-Name': 'x' }, { 'x-forwarded-for': '198.51.100.7' })).status, 404);
    assert.equal((await fetch(`${h.base}/radius/authorize`, { headers: { authorization: auth } })).status, 404);
  });
});
