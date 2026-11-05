// Decides whether a school account may join the WiFi, and on which VLAN. Used by the
// sign-in page (portal.js) and by FreeRADIUS (through radius-api.js) on every login.
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

/** The SSID out of a Called-Station-Id like "AA-BB-CC-DD-EE-FF:Nexus Staff", or null. */
export function ssidFromCalledStation(value) {
  const m = /^(?:[0-9a-f]{2}[-:.]?){5}[0-9a-f]{2}:(.+)$/i.exec(String(value ?? '').trim());
  return m ? m[1] : null;
}

/** Finds the configured network for an SSID (exact, then ignoring case). */
export function findNetwork(networks, ssid) {
  if (!ssid) return null;
  if (Object.hasOwn(networks, ssid)) return { ssid, vlanId: networks[ssid] };
  const key = Object.keys(networks).find((k) => k.toLowerCase() === String(ssid).toLowerCase());
  return key ? { ssid: key, vlanId: networks[key] } : null;
}

/**
 * Whether an allowed person may use this network: each network is one VLAN, so their
 * rule's VLAN must be that network's. A rule without a VLAN may use any network.
 */
export function checkNetwork(networks, decision, ssid) {
  const net = findNetwork(networks, ssid);
  if (!net) return { ok: false, reason: `${ssid ? `"${ssid}"` : 'that network'} isn't a sign-in network`, message: "This network isn't set up for school sign-in." };
  if (decision.vlanId && decision.vlanId !== net.vlanId) {
    const right = Object.keys(networks).filter((k) => networks[k] === decision.vlanId);
    return {
      ok: false,
      reason: `rule "${decision.rule?.name}" is for VLAN ${decision.vlanId}, not ${net.ssid}`,
      message: right.length ? `Your account uses the ${right.map((r) => `“${r}”`).join(' or ')} network.` : "Your account can't use this network.",
    };
  }
  return { ok: true, ssid: net.ssid, vlanId: net.vlanId };
}

export function createAccess({ settings, directory = null, cacheMs = 5 * 60_000 }) {
  // Devices re-authenticate when they roam and when sessions end; caching the
  // decision for a few minutes spares the Google directory those repeat lookups.
  const cache = new TtlMap({ max: 20_000 });

  // A blocked person is told so on the sign-in page, with the reason the admin gave.
  const blocked = (e) => ({ allow: false, blocked: true, blockReason: settings.blockOf?.(e)?.reason ?? null, reason: 'blocked by an admin' });

  async function resolve(email) {
    let e = email.toLowerCase();
    // Real addresses are short; a long one only costs time in the rules' regexes.
    if (e.length > 128) return { allow: false, reason: 'username too long' };
    if (settings.isBlocked(e)) return blocked(e);
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
        if (settings.isBlocked(e)) return blocked(e);
      }
    }
    const decision = evaluate(settings.current().compiledPolicy, { email: e, orgUnitPath });
    if (!decision.allow) {
      return { allow: false, rule: decision.rule, orgUnitPath, reason: decision.rule ? `rule "${decision.rule.name}"` : 'no rule allows them' };
    }
    return { allow: true, email: e, rule: decision.rule, orgUnitPath, vlanId: decision.rule?.vlanId ?? null };
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
