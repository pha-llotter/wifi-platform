// SmartZone public API client, limited to what DPSK key management needs.
// Shapes follow the v9_1–v13_1 API (verified against SmartZone 7.1 by the
// wifinity/python-ruckus-smartzone SDK):
//   POST   /serviceTicket                         {username, password} → {serviceTicket}
//   POST   /rkszones/{z}/wlans/{w}/dpsk/batchGenUnbound {amount, userName, vlanId, passphraseList}
//   GET    /rkszones/{z}/wlans/{w}/dpsk           paged {list, hasMore}
//   GET    /rkszones/{z}/wlans/{w}/dpsk/{id}      the paged shape with one item
//   POST   /rkszones/{z}/wlans/{w}/dpsk           {idList} deletes keys (there is no DELETE)
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';

const normalizeFingerprint = (s) => String(s ?? '').replace(/[^0-9a-f]/gi, '').toUpperCase();

/** Connects once and returns the SHA-256 fingerprint of the certificate a host presents. */
export function fetchFingerprint(host, port = 8443) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername: /^[\d.]+$/.test(host) ? undefined : host, rejectUnauthorized: false, timeout: 10_000 }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      resolve({ fingerprint256: cert.fingerprint256, subject: cert.subject?.CN, validTo: cert.valid_to });
    });
    socket.on('timeout', () => socket.destroy(new Error('timed out')));
    socket.on('error', reject);
  });
}

// With a pinned fingerprint, a connection is handed to the request only after the
// certificate matched, so the API password never goes to anyone else. This works with
// the vSZ's self-signed certificate, which normal verification would reject.
function pinnedAgent(fingerprint) {
  const want = normalizeFingerprint(fingerprint);
  const agent = new https.Agent({ keepAlive: true });
  agent.createConnection = (options, callback) => {
    let done = false;
    const finish = (err, socket) => {
      if (done) return;
      done = true;
      callback(err, socket);
    };
    const socket = tls.connect({ ...options, rejectUnauthorized: false });
    socket.once('secureConnect', () => {
      const got = socket.getPeerCertificate().fingerprint256;
      if (normalizeFingerprint(got) === want) return finish(null, socket);
      socket.destroy();
      finish(new Error(`the vSZ certificate doesn't match the pinned fingerprint (it presented ${got})`));
    });
    socket.once('error', (err) => finish(err));
  };
  return agent;
}

export class VszError extends Error {
  constructor(message, status, data) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

export function createVszClient({
  host,
  port = 8443,
  protocol = 'https',
  apiVersion = 'v9_1',
  username,
  password,
  zoneId,
  wlanId,
  tlsVerify = false,
  tlsFingerprint = null,
  timeoutMs = 15_000,
}) {
  const transport = protocol === 'https' ? https : http;
  const agent =
    protocol === 'https' && tlsFingerprint
      ? pinnedAgent(tlsFingerprint)
      : new transport.Agent({ keepAlive: true, rejectUnauthorized: tlsVerify });
  const base = `/wsg/api/public/${apiVersion}`;
  const dpskPath = `/rkszones/${encodeURIComponent(zoneId)}/wlans/${encodeURIComponent(wlanId)}/dpsk`;
  // How the connection to the vSZ is protected, shown on the dashboard.
  const security = protocol !== 'https' ? 'plain-http' : tlsFingerprint ? 'pinned' : tlsVerify ? 'verified' : 'unverified';
  const health = { lastOk: null, lastError: null, lastErrorAt: null, security };
  let ticket = null;

  function request(method, path, { body, query } = {}) {
    return new Promise((resolve, reject) => {
      const qs = query ? `?${new URLSearchParams(query)}` : '';
      const data = body === undefined ? null : JSON.stringify(body);
      const req = transport.request(
        {
          host,
          port,
          method,
          path: `${base}${path}${qs}`,
          agent,
          timeout: timeoutMs,
          headers: {
            Accept: 'application/json',
            ...(data && { 'Content-Type': 'application/json;charset=UTF-8', 'Content-Length': Buffer.byteLength(data) }),
          },
        },
        (res) => {
          const chunks = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let json = null;
            try {
              json = text ? JSON.parse(text) : null;
            } catch {
              json = { message: text.slice(0, 200) };
            }
            resolve({ status: res.statusCode, data: json });
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error('vSZ API request timed out')));
      req.on('error', reject);
      req.end(data ?? undefined);
    });
  }

  function fail(err) {
    health.lastError = err.message;
    health.lastErrorAt = Date.now();
    throw err;
  }

  async function logon() {
    let r;
    try {
      r = await request('POST', '/serviceTicket', { body: { username, password } });
    } catch (err) {
      return fail(new VszError(`Can't reach the vSZ at ${host}:${port}: ${err.message}`, 0));
    }
    if (r.status !== 200 || !r.data?.serviceTicket) {
      return fail(new VszError(`vSZ sign-in failed (HTTP ${r.status}): ${r.data?.message ?? 'check the API username and password'}`, r.status, r.data));
    }
    ticket = r.data.serviceTicket;
  }

  async function call(method, path, { body, query } = {}, retried = false) {
    if (!ticket) await logon();
    let r;
    try {
      r = await request(method, path, { body, query: { ...query, serviceTicket: ticket } });
    } catch (err) {
      return fail(new VszError(`Can't reach the vSZ at ${host}:${port}: ${err.message}`, 0));
    }
    if (r.status === 401 && !retried) {
      ticket = null;
      return call(method, path, { body, query }, true);
    }
    if (r.status >= 400) {
      const detail = r.data?.message ?? r.data?.errorType ?? '';
      return fail(new VszError(`vSZ API ${method} ${path.split('?')[0]} failed (HTTP ${r.status})${detail ? `: ${detail}` : ''}`, r.status, r.data));
    }
    health.lastOk = Date.now();
    return r.data;
  }

  async function paginate(path) {
    const out = [];
    for (let index = 0; ; ) {
      const page = await call('GET', path, { query: { index, listSize: 1000 } });
      const list = page?.list ?? [];
      out.push(...list);
      if (!page?.hasMore || !list.length) return out;
      index += list.length;
    }
  }

  return {
    health,

    /** Creates one key; the controller generates the passphrase unless one is given. */
    async createKey({ userName, vlanId = null, passphrase = null }) {
      const body = { amount: 1, userName };
      if (vlanId) body.vlanId = vlanId;
      if (passphrase) body.passphraseList = [passphrase];
      const result = await call('POST', `${dpskPath}/batchGenUnbound`, { body });
      const key = result?.dpskInfoList?.[0];
      if (!key?.id) fail(new VszError('vSZ created no key', 0, result));
      return key;
    },

    /** Returns the key (with passphrase and bound MAC) or null if it no longer exists. */
    async getKey(id) {
      try {
        const result = await call('GET', `${dpskPath}/${encodeURIComponent(id)}`);
        return Array.isArray(result?.list) ? result.list[0] ?? null : result;
      } catch (err) {
        if (err.status === 404 || (err.status === 403 && err.data?.errorCode === 211)) return null;
        throw err;
      }
    },

    listKeys: () => paginate(dpskPath),

    async deleteKeys(ids) {
      if (!ids.length) return 0;
      const result = await call('POST', dpskPath, { body: { idList: ids } });
      return Number(result?.resultCount ?? 0);
    },

    listZones: () => paginate('/rkszones'),
    listWlans: (zone) => paginate(`/rkszones/${encodeURIComponent(zone)}/wlans`),

    async close() {
      if (!ticket) return;
      await request('DELETE', '/serviceTicket', { query: { serviceTicket: ticket } }).catch(() => {});
      ticket = null;
    },
  };
}
