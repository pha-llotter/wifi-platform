// Checks a school password with Google Secure LDAP, for the portal's sign-in form:
//   1. bind as the LDAP client (its access credentials; the client certificate is the TLS key)
//   2. search for the person's entry by email
//   3. bind as that entry with the password they typed: Google answers success or
//      "invalid credentials"
// Only what this needs of LDAP is implemented: simple binds and one equality search.
import tls from 'node:tls';

function berLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const tlv = (tag, content) => Buffer.concat([Buffer.from([tag]), berLength(content.length), content]);
const str = (s, tag = 0x04) => tlv(tag, Buffer.from(String(s), 'utf8'));
const int = (n, tag = 0x02) => tlv(tag, Buffer.from([n])); // 0..127 is all this needs
const message = (id, op) => tlv(0x30, Buffer.concat([int(id), op]));

export const bindRequest = (id, name, password) =>
  message(id, tlv(0x60, Buffer.concat([int(3), str(name), str(password, 0x80)])));

export const searchRequest = (id, baseDn, email) =>
  message(id, tlv(0x63, Buffer.concat([
    str(baseDn), int(2, 0x0a), int(0, 0x0a), int(2), int(10), tlv(0x01, Buffer.from([0])),
    tlv(0xa3, Buffer.concat([str('mail'), str(email)])), // (mail=…)
    tlv(0x30, str('1.1')), // no attributes, only the entry's DN
  ])));

const unbindRequest = (id) => message(id, Buffer.from([0x42, 0x00]));

function readTlv(buf, at) {
  if (at + 2 > buf.length) return null;
  let len = buf[at + 1];
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (start + n > buf.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[start + i];
    start += n;
  }
  if (start + len > buf.length) return null;
  return { tag: buf[at], start, end: start + len };
}

/** Splits complete LDAP messages off the front of buf: { messages: [{id, op, …}], rest }. */
export function parseMessages(buf) {
  const messages = [];
  let at = 0;
  for (;;) {
    const msg = readTlv(buf, at);
    if (!msg) break;
    const idT = readTlv(buf, msg.start);
    const opT = idT && readTlv(buf, idT.end);
    if (!opT) throw new Error('unreadable LDAP reply');
    let id = 0;
    for (let i = idT.start; i < idT.end; i++) id = id * 256 + buf[i];
    const out = { id, op: opT.tag };
    const first = readTlv(buf, opT.start);
    if (opT.tag === 0x64 && first) {
      out.dn = buf.subarray(first.start, first.end).toString('utf8');
    } else if ((opT.tag === 0x61 || opT.tag === 0x65 || opT.tag === 0x78) && first) {
      out.code = first.end > first.start ? buf[first.end - 1] : -1;
      const dn = readTlv(buf, first.end);
      const text = dn && readTlv(buf, dn.end);
      out.message = text ? buf.subarray(text.start, text.end).toString('utf8') : '';
    }
    messages.push(out);
    at = msg.end;
  }
  return { messages, rest: buf.subarray(at) };
}

export class LdapError extends Error {}

/**
 * Returns verify(email, password) → { ok: true, dn } or { ok: false, reason }.
 * Throws LdapError when Google can't be asked (network, certificate, access credentials).
 */
export function createLdapVerifier({ host = 'ldap.google.com', port = 636, cert, key, identity = '', password = '', baseDn, timeoutMs = 10_000, connect = tls.connect }) {
  return async function verify(email, userPassword) {
    // An empty password would be an anonymous bind, which "succeeds": never send one.
    if (!userPassword) return { ok: false, reason: 'no password' };
    if (!email) return { ok: false, reason: 'no email' };

    const socket = connect({ host, port, servername: host, cert, key });
    let buf = Buffer.alloc(0);
    const queue = [];
    let waiter = null;
    let failure = null;
    const wake = () => {
      if (waiter) {
        const w = waiter;
        waiter = null;
        w();
      }
    };
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      try {
        const { messages, rest } = parseMessages(buf);
        buf = rest;
        queue.push(...messages);
      } catch (err) {
        failure = new LdapError(err.message);
      }
      wake();
    });
    socket.on('error', (err) => {
      failure = new LdapError(`Can't reach Google Secure LDAP: ${err.message}`);
      wake();
    });
    socket.on('end', () => {
      failure ??= new LdapError('Google closed the LDAP connection (is the client certificate accepted?)');
      wake();
    });
    const timer = setTimeout(() => {
      failure = new LdapError(`Google Secure LDAP didn't answer within ${timeoutMs / 1000}s`);
      wake();
    }, timeoutMs);

    // The next message for this id (a notice of disconnection, id 0, ends everything).
    async function next(id) {
      for (;;) {
        const i = queue.findIndex((m) => m.id === id || m.id === 0);
        if (i >= 0) {
          const m = queue.splice(i, 1)[0];
          if (m.id === 0) throw new LdapError(`Google ended the LDAP session: ${m.message || 'no reason given'}`);
          return m;
        }
        if (failure) throw failure;
        await new Promise((r) => (waiter = r));
      }
    }

    try {
      await new Promise((resolve, reject) => {
        socket.once('secureConnect', resolve);
        socket.once('error', reject);
      }).catch((err) => {
        throw new LdapError(`Can't reach Google Secure LDAP: ${err.message}`);
      });

      socket.write(bindRequest(1, identity, password));
      const asClient = await next(1);
      if (asClient.code !== 0) {
        throw new LdapError(`Google refused the LDAP client's access credentials: ${asClient.message || `result ${asClient.code}`}`);
      }

      socket.write(searchRequest(2, baseDn, email));
      const entries = [];
      for (;;) {
        const m = await next(2);
        if (m.op === 0x64) entries.push(m.dn);
        else if (m.op === 0x65) {
          if (m.code !== 0) throw new LdapError(`Google refused the LDAP search: ${m.message || `result ${m.code}`}`);
          break;
        }
      }
      if (entries.length !== 1) return { ok: false, reason: entries.length ? 'more than one account has that email' : 'not found' };

      socket.write(bindRequest(3, entries[0], userPassword));
      const asUser = await next(3);
      if (asUser.code === 0) return { ok: true, dn: entries[0] };
      if (asUser.code === 49) return { ok: false, reason: 'wrong password' };
      throw new LdapError(`Google couldn't check the password: ${asUser.message || `result ${asUser.code}`}`);
    } finally {
      clearTimeout(timer);
      try {
        socket.end(unbindRequest(4));
      } catch {}
      socket.destroy();
    }
  };
}
