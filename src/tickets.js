// One-time passwords for the portal. After someone's school password checks out, the
// portal issues a random ticket and hands it to the vSZ as the login's password; the
// vSZ sends it to FreeRADIUS, and the RADIUS API redeems it here. A ticket is valid for
// two minutes and works once, so RADIUS accepts nothing the portal didn't just issue.
import crypto from 'node:crypto';
import { TtlMap } from './store.js';

export function createTickets({ ttlMs = 2 * 60_000 } = {}) {
  const pending = new TtlMap({ max: 5_000 });

  function issue(email, ssid) {
    const ticket = crypto.randomBytes(24).toString('base64url');
    pending.set(email.toLowerCase(), { ticket, ssid }, ttlMs);
    return ticket;
  }

  /** The ticket's details if it's the one just issued to this email, and then it's gone. */
  function redeem(email, ticket) {
    const key = String(email ?? '').toLowerCase();
    const entry = pending.get(key);
    if (!entry || typeof ticket !== 'string') return null;
    const a = Buffer.from(entry.ticket);
    const b = Buffer.from(ticket);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    pending.delete(key);
    return entry;
  }

  return { issue, redeem, close: () => pending.close() };
}
