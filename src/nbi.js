// Client for the SmartZone WISPr Northbound Portal Interface (POST /portalintf), which
// the portal uses to let a signed-in device on to the network. The vSZ answers a Login by
// sending FreeRADIUS an Access-Request with the username and one-time password given
// here, so the platform's RADIUS API (radius-api.js) has the last word.
//
// The vSZ's address is set in config.json and never taken from the redirect: the
// redirect's nbiIP comes from the device's browser, and the NBI password goes with every
// request. With a pinned fingerprint, a connection is only used once the certificate matched.
import http from 'node:http';
import https from 'node:https';
import { pinnedAgent } from './vsz.js';

export const NBI = {
  AUTHORIZED: 101,
  LOGIN_SUCCEEDED: 201,
  AUTH_PENDING: 202,
  NOT_FOUND: 300,
  LOGIN_FAILED: 301,
  BAD_REQUEST: 302,
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function createNbiClient({ host, port = 9443, protocol = 'https', password, tlsFingerprint = null, tlsVerify = false, timeoutMs = 10_000 }) {
  const transport = protocol === 'https' ? https : http;
  const agent =
    protocol === 'https' && tlsFingerprint ? pinnedAgent(tlsFingerprint) : new transport.Agent({ keepAlive: true, rejectUnauthorized: tlsVerify });
  const health = { lastOk: null, lastError: null, lastErrorAt: null, security: protocol !== 'https' ? 'plain-http' : tlsFingerprint ? 'pinned' : tlsVerify ? 'verified' : 'unverified' };

  function post(body) {
    return new Promise((resolve, reject) => {
      const data = JSON.stringify(body);
      const req = transport.request(
        {
          host,
          port,
          path: '/portalintf',
          method: 'POST',
          agent,
          timeout: timeoutMs,
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
        },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            try {
              const json = JSON.parse(text);
              health.lastOk = Date.now();
              resolve({ code: Number(json.ResponseCode), message: json.ReplyMessage ?? '', raw: json });
            } catch {
              reject(new Error(`the vSZ portal interface answered HTTP ${res.statusCode}: ${text.slice(0, 200)}`));
            }
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error('the vSZ portal interface timed out')));
      req.on('error', reject);
      req.end(data);
    });
  }

  async function call(body) {
    try {
      return await post(body);
    } catch (err) {
      health.lastError = err.message;
      health.lastErrorAt = Date.now();
      throw new Error(`Can't reach the vSZ portal interface at ${host}:${port}: ${err.message}`);
    }
  }

  const request = (type, ue, extra = {}) => ({
    Vendor: 'ruckus',
    RequestPassword: password,
    APIVersion: '1.0',
    RequestCategory: 'UserOnlineControl',
    RequestType: type,
    'UE-IP': ue.ip,
    'UE-MAC': ue.mac,
    'UE-Proxy': ue.proxy ?? '0',
    ...extra,
  });

  const login = (ue, username, pass) => call(request('Login', ue, { 'UE-Username': username, 'UE-Password': pass }));
  const status = (ue) => call(request('Status', ue));
  const logout = (ue) => call(request('Logout', ue));

  /** Logs the device in and waits (briefly) until the vSZ says it's authorised. */
  async function loginAndWait(ue, username, pass, { attempts = 6, intervalMs = 1000 } = {}) {
    const first = await login(ue, username, pass);
    if (first.code === NBI.LOGIN_SUCCEEDED || first.code === NBI.AUTHORIZED) return { ok: true, ...first };
    if (first.code !== NBI.AUTH_PENDING) return { ok: false, ...first };
    for (let i = 0; i < attempts; i++) {
      await sleep(intervalMs);
      const s = await status(ue);
      if (s.code === NBI.AUTHORIZED) return { ok: true, ...s };
      if (s.code >= 300) return { ok: false, ...s };
    }
    return { ok: false, code: NBI.AUTH_PENDING, message: 'the vSZ did not confirm the login in time' };
  }

  return { login, status, logout, loginAndWait, health };
}
