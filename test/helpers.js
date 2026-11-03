// A whole platform wired up in memory, with a fake vSZ and stubbed Google sign-in.
import http from 'node:http';
import { createFakeVsz } from '../dev/fake-vsz.js';
import { createAccess } from '../src/access.js';
import { createAdmin } from '../src/admin.js';
import { createApp } from '../src/app.js';
import { normalizeConfig } from '../src/config.js';
import { openDb } from '../src/db.js';
import * as google from '../src/google.js';
import { createKeyService } from '../src/keys.js';
import { createRadiusApi } from '../src/radius-api.js';
import { createSettings } from '../src/settings.js';
import { createVszClient } from '../src/vsz.js';

const fakeJwt = (claims) => `x.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.sig`;

export async function startPlatform(extra = {}) {
  const h = { claims: {}, users: new Map() };
  h.vsz = createFakeVsz();
  const port = await h.vsz.listen();
  h.config = normalizeConfig({
    publicUrl: 'http://portal.test',
    google: { clientId: 'cid', clientSecret: 'cs', allowedDomains: ['school.org'], directory: { enabled: true, serviceAccountKeyFile: 'x', adminEmail: 'a@school.org' } },
    radius: { apiToken: 'test-token-0123456789abcdef' },
    dpsk: { ...h.vsz.config, port, ssid: 'PHA-Guest', guestVlanId: 50, maxGuestDays: 7 },
    admin: { emails: ['it@school.org'] },
    policy: { rules: [{ name: 'Staff', orgUnit: '/Staff', vlanId: 20 }], default: { vlanId: 30 } },
    ...extra,
  });
  h.db = openDb(':memory:');
  h.settings = createSettings({ config: h.config, db: h.db });
  const log = (event, data) => h.db.record(event, data);
  const directory = { getUser: async (email) => h.users.get(email) ?? null };
  h.access = createAccess({ settings: h.settings, directory });
  h.keys = createKeyService({ config: h.config, db: h.db, vsz: createVszClient(h.config.dpsk), log });
  const oauth = { ...google, exchangeCode: async () => fakeJwt(h.claims) };
  h.admin = createAdmin({ config: h.config, db: h.db, settings: h.settings, keys: h.keys, access: h.access, log, oauth });
  h.radiusApi = createRadiusApi({ config: h.config, db: h.db, access: h.access, settings: h.settings, log });
  h.app = createApp({ admin: h.admin, radiusApi: h.radiusApi, log });
  h.server = http.createServer(h.app.handle);
  await new Promise((r) => h.server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${h.server.address().port}`;

  h.req = async (path, { method = 'GET', cookie, body, csrf } = {}) => {
    const headers = {};
    if (cookie) headers.cookie = cookie;
    if (csrf) headers['x-csrf-token'] = csrf;
    if (body) headers['content-type'] = 'application/json';
    const res = await fetch(base + path, { method, headers, body: body && JSON.stringify(body), redirect: 'manual' });
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {}
    return { res, text, json, cookies: res.headers.getSetCookie().map((c) => c.split(';')[0]) };
  };

  h.loginAdmin = async (email = 'it@school.org') => {
    const start = await h.req('/admin/login');
    const authUrl = new URL(start.res.headers.get('location'));
    h.claims = { iss: 'https://accounts.google.com', aud: 'cid', exp: Date.now() / 1000 + 300, nonce: authUrl.searchParams.get('nonce'), email, email_verified: true, hd: email.split('@')[1] };
    const done = await h.req(`/admin/oauth/callback?code=c&state=${authUrl.searchParams.get('state')}`, { cookie: start.cookies.join('; ') });
    const cookie = done.cookies.find((c) => c.startsWith('wp_admin='));
    if (!cookie) return { done };
    return { done, cookie, csrf: (await h.req('/admin/api/me', { cookie })).json.csrf };
  };
  h.api = (a, path, body = {}) => h.req(`/admin/api${path}`, { method: 'POST', cookie: a.cookie, csrf: a.csrf, body });

  h.close = () => {
    h.server.close();
    h.radiusApi.close();
    h.admin.close();
    h.db.close();
    h.vsz.close();
  };
  return h;
}
