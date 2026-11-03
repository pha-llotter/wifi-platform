// Decides whether a school account may join the WiFi, and on which VLAN. Used by
// FreeRADIUS (through radius-api.js) on every 802.1X login.
import { evaluate } from './policy.js';
import { TtlMap } from './store.js';

/**
 * Turns what someone typed as their WiFi username into their Google email:
 * "T.Smith" → "t.smith@phahs.org.za", "PHAHS\t.smith" → the same, emails pass through.
 */
export function normalizeUsername(name, defaultDomain) {
  let u = String(name ?? '').trim().toLowerCase();
  u = u.replace(/^[^\\]+\\/, ''); // DOMAIN\user, as some Windows devices send it
  if (u && !u.includes('@') && defaultDomain) u = `${u}@${defaultDomain}`;
  return u;
}

export function createAccess({ settings, directory = null, cacheMs = 5 * 60_000 }) {
  // Devices re-authenticate when they roam and when sessions end; caching the
  // decision for a few minutes spares the Google directory those repeat lookups.
  const cache = new TtlMap({ max: 20_000 });

  async function resolve(email) {
    let e = email.toLowerCase();
    if (settings.isBlocked(e)) return { allow: false, reason: 'blocked by an admin' };
    const domain = e.split('@')[1];
    if (!settings.current().allowedDomains.includes(domain)) return { allow: false, reason: `${domain || 'that username'} isn't an allowed domain` };
    let orgUnitPath;
    if (directory) {
      const user = await directory.getUser(e);
      if (!user) return { allow: false, reason: 'not in the Google directory' };
      if (user.suspended || user.archived) return { allow: false, reason: 'account suspended or archived' };
      orgUnitPath = user.orgUnitPath;
      // Someone logging in with an alias is judged as their primary address, so a block
      // or an email rule can't be sidestepped with another name for the same account.
      const primary = String(user.email ?? '').toLowerCase();
      if (primary && primary !== e) {
        e = primary;
        if (settings.isBlocked(e)) return { allow: false, reason: 'blocked by an admin' };
      }
    }
    const decision = evaluate(settings.current().compiledPolicy, { email: e, orgUnitPath });
    if (!decision.allow) {
      return { allow: false, rule: decision.rule, orgUnitPath, reason: decision.rule ? `rule "${decision.rule.name}"` : 'no rule allows them' };
    }
    return { allow: true, rule: decision.rule, orgUnitPath, vlanId: decision.rule?.vlanId ?? null };
  }

  async function check(email) {
    const hit = cache.get(email);
    if (hit) return hit;
    return cache.set(email, await resolve(email), cacheMs);
  }

  return {
    resolve,
    check,
    /** Drops cached decisions, e.g. after a block or a rule change. */
    forget: (email) => (email ? cache.delete(email.toLowerCase()) : cache.clear()),
  };
}
