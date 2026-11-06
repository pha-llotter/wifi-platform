// Stand-in for the SmartZone public API's DPSK endpoints, for tests and trying the
// platform without a controller. Behaves like SmartZone 7.1 as documented by the
// wifinity/python-ruckus-smartzone SDK: ticket auth, batchGenUnbound, paged list,
// list-shaped detail, delete by POSTing an idList, unique passphrases.
//
//   node dev/fake-vsz.js        (listens on 127.0.0.1:18443, matches config.dev.example.json)
import crypto from 'node:crypto';
import http from 'node:http';
import { pathToFileURL } from 'node:url';

export function createFakeVsz({ port = 0, username = 'api', password = 'api-pass', zoneId = 'zone-1', wlanId = 'wlan-1', ssid = 'Nexus' } = {}) {
  const tickets = new Set();
  const keys = new Map();
  const calls = [];
  let supportsGroup = true;
  const alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const genPassphrase = () => Array.from(crypto.randomBytes(16), (b) => alphabet[b % alphabet.length]).join('');
  const dpskBase = `/rkszones/${zoneId}/wlans/${wlanId}/dpsk`;

  function reply(res, status, body) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(body === undefined ? '' : JSON.stringify(body));
  }

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://vsz');
      const m = url.pathname.match(/^\/wsg\/api\/public\/v\d+_\d+(\/.*)$/);
      if (!m) return reply(res, 404, { message: 'not found' });
      const path = m[1];
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};
      calls.push({ method: req.method, path, body });

      if (path === '/serviceTicket' && req.method === 'POST') {
        if (body.username !== username || body.password !== password) return reply(res, 401, { message: 'Invalid credentials' });
        const ticket = `ST-${crypto.randomBytes(8).toString('hex')}`;
        tickets.add(ticket);
        return reply(res, 200, { serviceTicket: ticket, controllerVersion: '7.1.1.0.551' });
      }
      if (!tickets.has(url.searchParams.get('serviceTicket'))) return reply(res, 401, { message: 'Invalid service ticket' });
      if (path === '/serviceTicket' && req.method === 'DELETE') {
        tickets.delete(url.searchParams.get('serviceTicket'));
        return reply(res, 200, {});
      }
      if (path === '/rkszones' && req.method === 'GET') {
        return reply(res, 200, { totalCount: 1, hasMore: false, list: [{ id: zoneId, name: 'Default Zone' }] });
      }
      if (path === `/rkszones/${zoneId}/wlans` && req.method === 'GET') {
        return reply(res, 200, { totalCount: 1, hasMore: false, list: [{ id: wlanId, name: ssid, ssid }] });
      }
      if (path === `${dpskBase}/batchGenUnbound` && req.method === 'POST') {
        // The real vSZ's rule for a DPSK user name (an HTTP 422 from the live controller).
        if (!/^[A-Za-z0-9\-_.@#$]{2,64}$/.test(String(body.userName ?? ''))) {
          return reply(res, 422, { errorCode: 101, message: `The userName '${body.userName}' is invalid. Accept characters: [A-Z, a-z, 0-9, -, _, ., @, #, $] and the length must be between 2 ~ 64` });
        }
        const passphrase = body.passphraseList?.[0] ?? genPassphrase();
        if ([...keys.values()].some((k) => k.passphrase === passphrase)) {
          return reply(res, 422, { errorCode: 302, message: 'passphrase is already existed' });
        }
        const key = {
          id: crypto.randomUUID(),
          userName: body.userName,
          passphrase,
          vlanId: body.vlanId ?? null,
          // supportsGroup = false stands in for a vSZ that ignores the option.
          groupDpsk: body.groupDpsk === true && supportsGroup,
          macAddress: null,
          wlanId,
          creationDateTime: Date.now(),
          expirationDateTime: null,
        };
        keys.set(key.id, key);
        return reply(res, 201, { resultCount: 1, dpskInfoList: [key] });
      }
      if (path === dpskBase && req.method === 'GET') {
        const all = [...keys.values()];
        const index = Number(url.searchParams.get('index') ?? 0);
        const size = Number(url.searchParams.get('listSize') ?? 100);
        const list = all.slice(index, index + size);
        return reply(res, 200, { totalCount: all.length, hasMore: index + size < all.length, firstIndex: index, list });
      }
      if (path === dpskBase && req.method === 'POST') {
        let n = 0;
        for (const id of body.idList ?? []) n += keys.delete(id) ? 1 : 0;
        return reply(res, 200, { resultCount: n });
      }
      const detail = path.startsWith(`${dpskBase}/`) && path.slice(dpskBase.length + 1);
      if (detail && req.method === 'GET') {
        const key = keys.get(detail);
        if (!key) return reply(res, 403, { errorCode: 211, message: 'Object not found' });
        return reply(res, 200, { totalCount: 1, hasMore: false, list: [key] });
      }
      reply(res, 404, { message: `no route ${req.method} ${path}` });
    });
  });

  return {
    keys,
    calls,
    config: { host: '127.0.0.1', protocol: 'http', username, password, zoneId, wlanId, ssid },
    /** Simulates a device connecting with a key, which binds the key to its MAC. */
    bind(id, mac) {
      keys.get(id).macAddress = mac;
    },
    expireTickets: () => tickets.clear(),
    /** false: behave like a vSZ that ignores groupDpsk and makes one-device keys. */
    setGroupSupport: (on) => {
      supportsGroup = on;
    },
    listen: () => new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve(server.address().port))),
    close: () => server.close(),
  };
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const vsz = createFakeVsz({ port: 18443, username: 'dev', password: 'dev' });
  await vsz.listen();
  console.log('[fake-vsz] SmartZone API on http://127.0.0.1:18443 (user dev / dev, zone-1, wlan-1, SSID Nexus)');
}
