// Google sign-in (OpenID Connect, authorization code + PKCE) and the optional
// Admin SDK Directory lookup (org units, suspended accounts) and Gmail alerts, both
// through one service account with domain-wide delegation.
import crypto from 'node:crypto';
import fs from 'node:fs';

const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const DIRECTORY_SCOPE = 'https://www.googleapis.com/auth/admin.directory.user.readonly';
const GMAIL_SEND_SCOPE = 'https://www.googleapis.com/auth/gmail.send';
const ISSUERS = ['https://accounts.google.com', 'accounts.google.com'];

export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

export function pkceChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

export function buildAuthUrl({ clientId, redirectUri, state, nonce, codeVerifier, allowedDomains }) {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: pkceChallenge(codeVerifier),
    code_challenge_method: 'S256',
    prompt: 'select_account',
    // Only a hint for Google's account picker; the hd claim is enforced in checkIdToken.
    hd: allowedDomains.length === 1 ? allowedDomains[0] : '*',
  });
  return `${AUTH_URL}?${params}`;
}

export async function exchangeCode({ clientId, clientSecret, redirectUri, code, codeVerifier }) {
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      code_verifier: codeVerifier,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
    }),
    signal: AbortSignal.timeout(10_000),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !body.id_token) {
    throw new Error(`token exchange failed: ${body.error_description ?? body.error ?? `HTTP ${res.status}`}`);
  }
  return body.id_token;
}

// The ID token comes straight from Google's token endpoint over TLS, so per Google's
// guidance we can read its claims without verifying the signature ourselves.
export function decodeJwtPayload(jwt) {
  const part = String(jwt).split('.')[1];
  if (!part) throw new Error('malformed ID token');
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

export function checkIdToken(claims, { clientId, nonce, allowedDomains, now = Date.now() / 1000 }) {
  const fail = (reason, userMessage = 'Google sign-in could not be verified. Please try again.') => ({
    ok: false,
    reason,
    userMessage,
  });
  if (!ISSUERS.includes(claims.iss)) return fail('unexpected issuer');
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(clientId)) return fail('wrong audience');
  if (typeof claims.exp !== 'number' || claims.exp < now - 60) return fail('token expired');
  if (!nonce || claims.nonce !== nonce) return fail('nonce mismatch');
  if (claims.email_verified !== true || !claims.email) return fail('email not verified');
  const hd = String(claims.hd ?? '').toLowerCase();
  const domains = allowedDomains.join(' or ');
  if (!hd) {
    return fail('personal account', `That's a personal Google account. Sign in with your ${domains} account instead.`);
  }
  if (!allowedDomains.includes(hd)) {
    return fail(`domain ${hd} not allowed`, `Only ${domains} accounts can use this network.`);
  }
  return { ok: true, email: claims.email.toLowerCase(), name: claims.name ?? '', domain: hd };
}

/**
 * A Google service account with domain-wide delegation: issues access tokens that
 * act as a given Workspace user for a given scope. Shared by the directory lookup
 * and the alert mailer.
 */
export function createServiceAccount({ serviceAccountKeyFile }) {
  const key = JSON.parse(fs.readFileSync(serviceAccountKeyFile, 'utf8'));
  const cache = new Map();

  async function accessToken(scope, subject) {
    const id = `${scope}|${subject}`;
    const hit = cache.get(id);
    if (hit && hit.expires > Date.now() + 60_000) return hit.token;
    const now = Math.floor(Date.now() / 1000);
    const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const unsigned = `${enc({ alg: 'RS256', typ: 'JWT' })}.${enc({ iss: key.client_email, sub: subject, scope, aud: TOKEN_URL, iat: now, exp: now + 3600 })}`;
    const signature = crypto.sign('RSA-SHA256', Buffer.from(unsigned), key.private_key).toString('base64url');
    const res = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${signature}` }),
      signal: AbortSignal.timeout(10_000),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`Google token for ${subject} failed: ${body.error_description ?? body.error ?? res.status}`);
    cache.set(id, { token: body.access_token, expires: Date.now() + body.expires_in * 1000 });
    return body.access_token;
  }

  return { accessToken };
}

export function createDirectoryClient({ serviceAccount, adminEmail }) {
  async function getUser(email) {
    const url =
      `https://admin.googleapis.com/admin/directory/v1/users/${encodeURIComponent(email)}` +
      '?projection=basic&fields=primaryEmail,orgUnitPath,suspended,archived';
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${await serviceAccount.accessToken(DIRECTORY_SCOPE, adminEmail)}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (res.status === 404) return null;
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`directory lookup failed: ${body.error?.message ?? res.status}`);
    return {
      email: body.primaryEmail,
      orgUnitPath: body.orgUnitPath ?? '/',
      suspended: Boolean(body.suspended),
      archived: Boolean(body.archived),
    };
  }

  return { getUser };
}

/** Sends plain-text mail as `from` through the Gmail API (scope gmail.send). */
export function createMailer({ serviceAccount, from }) {
  const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
  async function send({ to, subject, text }) {
    const message = [
      `From: ${from}`,
      `To: ${to.join(', ')}`,
      `Subject: =?UTF-8?B?${b64(subject)}?=`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=UTF-8',
      'Content-Transfer-Encoding: base64',
      '',
      b64(text),
    ].join('\r\n');
    const res = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', {
      method: 'POST',
      headers: { Authorization: `Bearer ${await serviceAccount.accessToken(GMAIL_SEND_SCOPE, from)}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw: Buffer.from(message).toString('base64url') }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(`Gmail send failed: ${body.error?.message ?? res.status}`);
    }
  }
  return { send };
}
