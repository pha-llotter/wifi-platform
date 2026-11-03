import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildAuthUrl, checkIdToken, pkceChallenge } from '../src/google.js';

const opts = { clientId: 'cid', nonce: 'n1', allowedDomains: ['school.org'], now: 1000 };
const good = {
  iss: 'https://accounts.google.com',
  aud: 'cid',
  exp: 2000,
  nonce: 'n1',
  email: 'Teacher@School.org',
  email_verified: true,
  hd: 'school.org',
};

test('accepts a Workspace account from an allowed domain', () => {
  assert.deepEqual(checkIdToken(good, opts), { ok: true, email: 'teacher@school.org', name: '', domain: 'school.org' });
});

test('rejects personal, foreign-domain, unverified, replayed and stale tokens', () => {
  const cases = {
    'personal account': { hd: undefined },
    'domain other.org not allowed': { hd: 'other.org' },
    'email not verified': { email_verified: false },
    'nonce mismatch': { nonce: 'other' },
    'token expired': { exp: 500 },
    'wrong audience': { aud: 'someone-else' },
    'unexpected issuer': { iss: 'https://evil.example' },
  };
  for (const [reason, patch] of Object.entries(cases)) {
    const r = checkIdToken({ ...good, ...patch }, opts);
    assert.equal(r.ok, false);
    assert.equal(r.reason, reason);
    assert.ok(r.userMessage);
  }
});

test('auth URL carries PKCE, nonce and the domain hint', () => {
  const u = new URL(
    buildAuthUrl({ clientId: 'cid', redirectUri: 'https://w/cb', state: 's', nonce: 'n', codeVerifier: 'v', allowedDomains: ['school.org'] }),
  );
  assert.equal(u.searchParams.get('hd'), 'school.org');
  assert.equal(u.searchParams.get('nonce'), 'n');
  assert.equal(u.searchParams.get('code_challenge'), pkceChallenge('v'));
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
});
