// The settings people can change from the dashboard. config.json supplies the starting
// values; anything saved in the dashboard is stored in the database and wins.
import { compilePolicy, validatePolicy } from './policy.js';

const EDITABLE = ['allowedDomains', 'policy', 'branding', 'retentionDays', 'usageAlertGb'];

function validate(key, value, { directoryEnabled }) {
  switch (key) {
    case 'allowedDomains': {
      const list = Array.isArray(value) ? value.map((d) => String(d).trim().toLowerCase()).filter(Boolean) : [];
      if (!list.length) return { problems: ['Add at least one Google Workspace domain.'] };
      const bad = list.filter((d) => !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d));
      return bad.length ? { problems: [`Not a domain: ${bad.join(', ')}`] } : { value: [...new Set(list)] };
    }
    case 'policy': {
      const { policy, problems } = validatePolicy(value, { directoryEnabled });
      return problems.length ? { problems } : { value: policy };
    }
    case 'branding': {
      const name = String(value?.name ?? '').trim();
      return name && name.length <= 60 ? { value: { name } } : { problems: ['The network name must be 1–60 characters.'] };
    }
    case 'retentionDays': {
      return Number.isInteger(value) && value >= 7 && value <= 3650
        ? { value }
        : { problems: ['Keep records for between 7 and 3650 days.'] };
    }
    case 'usageAlertGb': {
      // null turns the daily usage alert off.
      if (value === null || value === '') return { value: null };
      const n = Number(value);
      return n >= 0.1 && n <= 10_000 ? { value: Math.round(n * 10) / 10 } : { problems: ['The daily usage alert must be between 0.1 and 10,000 GB, or empty for none.'] };
    }
    default:
      return { problems: [`${key} can't be changed here`] };
  }
}

export function createSettings({ config, db = null }) {
  const directoryEnabled = Boolean(config.google.directory?.enabled);
  let cache = null;

  function values() {
    const base = {
      allowedDomains: config.google.allowedDomains,
      policy: config.policy,
      branding: { name: config.branding.name },
      retentionDays: config.retentionDays,
      usageAlertGb: config.usage.alertGb,
    };
    if (!db) return base;
    for (const key of EDITABLE) {
      const stored = db.getSetting(key);
      if (stored !== undefined) base[key] = stored;
    }
    return base;
  }

  function current() {
    if (!cache) {
      const v = values();
      cache = {
        ...v,
        compiledPolicy: compilePolicy(v.policy),
        branding: { name: v.branding.name, school: config.branding.school, motto: config.branding.motto },
      };
    }
    return cache;
  }

  /** Validates every key first and saves nothing unless all of them pass. */
  function update(patch) {
    const problems = [];
    const clean = {};
    for (const [key, value] of Object.entries(patch)) {
      const r = validate(key, value, { directoryEnabled });
      if (r.problems) problems.push(...r.problems);
      else clean[key] = r.value;
    }
    if (problems.length) return { ok: false, problems };
    for (const [key, value] of Object.entries(clean)) db.setSetting(key, value);
    cache = null;
    return { ok: true };
  }

  return {
    current,
    update,
    isBlocked: (email) => (db ? db.isBlocked(email) : false),
    blockOf: (email) => (db?.blockOf ? db.blockOf(email) : null),
  };
}
