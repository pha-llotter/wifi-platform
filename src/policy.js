// Maps a person to a rule: whether they may log in to the school WiFi and which VLAN
// their devices go on. First match wins.

const intIn = (v, min, max) => Number.isInteger(v) && v >= min && v <= max;

function cleanLimits(src, where, problems) {
  const out = {};
  if (src.vlanId != null) {
    if (intIn(src.vlanId, 1, 4094)) out.vlanId = src.vlanId;
    else problems.push(`${where}: VLAN must be a number from 1 to 4094`);
  }
  return out;
}

/** Checks a policy (from config.json or the dashboard) and drops unknown fields. */
export function validatePolicy(policy, { directoryEnabled }) {
  const problems = [];
  if (!policy || typeof policy !== 'object') return { policy: null, problems: ['policy must be an object'] };
  const rules = [];
  for (const [i, r] of (policy.rules ?? []).entries()) {
    const where = `Rule ${i + 1}${r?.name ? ` "${r.name}"` : ''}`;
    if (!r || typeof r !== 'object') {
      problems.push(`${where}: not a rule`);
      continue;
    }
    const rule = { name: String(r.name ?? '').trim() };
    if (!rule.name || rule.name.length > 40) problems.push(`${where}: needs a name of up to 40 characters`);
    if (r.email) {
      try {
        new RegExp(r.email);
        rule.email = String(r.email);
      } catch {
        problems.push(`${where}: the email pattern is not a valid regular expression`);
      }
    }
    if (r.orgUnit) {
      if (!String(r.orgUnit).startsWith('/')) problems.push(`${where}: org unit paths start with /, e.g. /Staff`);
      else if (!directoryEnabled) problems.push(`${where}: matching on org unit needs the directory lookup turned on`);
      else rule.orgUnit = String(r.orgUnit);
    }
    if (r.deny) {
      rule.deny = true;
      if (r.message) rule.message = String(r.message).slice(0, 200);
    } else {
      Object.assign(rule, cleanLimits(r, where, problems));
    }
    rules.push(rule);
  }
  let fallback;
  if (policy.default === null) fallback = null;
  else if (policy.default === undefined) fallback = undefined;
  else fallback = cleanLimits(policy.default, 'Everyone else', problems);
  return { policy: { rules, default: fallback }, problems };
}

function compileRule(rule) {
  return {
    ...rule,
    emailRe: rule.email ? new RegExp(rule.email, 'i') : null,
    orgUnit: rule.orgUnit ? rule.orgUnit.replace(/\/+$/, '') || '/' : null,
  };
}

export function compilePolicy(policy = {}) {
  return {
    rules: (policy.rules ?? []).map(compileRule),
    // undefined → allow everyone with defaults; null → deny anyone no rule matched.
    fallback: policy.default === null ? null : compileRule({ name: 'default', ...policy.default }),
  };
}

function inOrgUnit(path, ou) {
  if (path === undefined) return false;
  if (ou === '/') return true;
  const p = path.toLowerCase();
  const o = ou.toLowerCase();
  return p === o || p.startsWith(`${o}/`);
}

function matches(rule, user) {
  if (rule.emailRe && !rule.emailRe.test(user.email)) return false;
  if (rule.orgUnit && !inOrgUnit(user.orgUnitPath, rule.orgUnit)) return false;
  return true;
}

export function evaluate(policy, user) {
  const rule = policy.rules.find((r) => matches(r, user)) ?? policy.fallback;
  if (!rule || rule.deny) return { allow: false, rule };
  return { allow: true, rule };
}
