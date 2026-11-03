// SQLite storage for the platform and its dashboard: what happened (events), who logs
// in to the school WiFi from which devices (logins), visitor keys on the guest SSID,
// blocked people and settings edited in the dashboard. Uses Node's built-in node:sqlite.
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  time INTEGER NOT NULL,
  type TEXT NOT NULL,
  category TEXT NOT NULL,
  email TEXT,
  mac TEXT,
  detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_time ON events(time);
CREATE INDEX IF NOT EXISTS events_email ON events(email, time);
CREATE INDEX IF NOT EXISTS events_category ON events(category, time);

-- Each device a person has logged in to the school WiFi from (802.1X).
CREATE TABLE IF NOT EXISTS logins (
  email TEXT NOT NULL,
  mac TEXT NOT NULL,
  first INTEGER NOT NULL,
  last INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  vlan_id INTEGER,
  rule TEXT,
  ap TEXT,
  PRIMARY KEY (email, mac)
);
CREATE INDEX IF NOT EXISTS logins_last ON logins(last);

-- Visitor keys (DPSK) on the guest SSID, each with an end date; email = the admin who
-- made it. The passphrase stays on the vSZ; only its id is kept here.
CREATE TABLE IF NOT EXISTS wifi_keys (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  label TEXT,
  vlan_id INTEGER,
  rule TEXT,
  mac TEXT,
  created INTEGER NOT NULL,
  kind TEXT NOT NULL,
  expires INTEGER,
  created_by TEXT
);

-- Connections reported by the vSZ's RADIUS accounting, with their running byte counts.
-- who = the school email, or a guest key's name on the guest SSID.
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  who TEXT NOT NULL,
  mac TEXT,
  ip TEXT,
  ap TEXT,
  nas TEXT,
  started INTEGER NOT NULL,
  updated INTEGER NOT NULL,
  stopped INTEGER,
  bytes_down INTEGER NOT NULL DEFAULT 0,
  bytes_up INTEGER NOT NULL DEFAULT 0,
  seconds INTEGER,
  cause TEXT
);
CREATE INDEX IF NOT EXISTS sessions_who ON sessions(who, started);
CREATE INDEX IF NOT EXISTS sessions_open ON sessions(stopped, updated);

-- Data used per person, device and day (the server's local date).
CREATE TABLE IF NOT EXISTS usage_daily (
  day TEXT NOT NULL,
  who TEXT NOT NULL,
  mac TEXT NOT NULL,
  bytes_down INTEGER NOT NULL DEFAULT 0,
  bytes_up INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (day, who, mac)
);
CREATE INDEX IF NOT EXISTS usage_daily_who ON usage_daily(who, day);

CREATE TABLE IF NOT EXISTS blocked (
  email TEXT PRIMARY KEY,
  reason TEXT,
  blocked_by TEXT,
  at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`;

const CATEGORY = {
  signed_in: 'signin',
  denied: 'denied',
  key_issued: 'keys',
  key_revoked: 'keys',
  key_missing: 'keys',
  key_reset: 'keys',
  keys_adopted: 'keys',
  key_sync: 'system',
  backup: 'system',
  alert_sent: 'system',
  usage_high: 'usage',
  admin: 'admin',
  admin_denied: 'admin',
  started: 'system',
  stopping: 'system',
};

export function categoryOf(event) {
  if (CATEGORY[event]) return CATEGORY[event];
  return /error|failed/.test(event) ? 'error' : null;
}

export function normalizeMac(mac) {
  if (!mac) return null;
  const hex = String(mac).replace(/[^0-9a-f]/gi, '').toLowerCase();
  return hex.length === 12 ? hex.match(/../g).join(':') : String(mac);
}

const parse = (row) => (row ? { ...row, detail: JSON.parse(row.detail ?? '{}') } : row);

/** The server's local calendar date, e.g. "2026-11-03". */
export function dayOf(ms) {
  const d = new Date(ms);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
const startOfDay = (now) => {
  const d = new Date(now);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
};

export function openDb(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 3000;');
  db.exec(SCHEMA);
  const q = (sql) => db.prepare(sql);

  const insertEvent = q('INSERT INTO events (time, type, category, email, mac, detail) VALUES (?, ?, ?, ?, ?, ?)');

  function record(event, data = {}, now = Date.now()) {
    const category = categoryOf(event);
    if (!category) return;
    const { email, mac, ...rest } = data;
    insertEvent.run(now, event, category, email ? String(email).toLowerCase() : null, normalizeMac(mac), JSON.stringify(rest));
  }

  /** Records a successful login. True when it's the device's first login today. */
  function recordLogin({ email, mac, vlanId = null, rule = null, ap = null }, now = Date.now()) {
    const m = normalizeMac(mac) ?? 'unknown';
    const prev = q('SELECT last FROM logins WHERE email = ? AND mac = ?').get(email, m);
    q(`INSERT INTO logins (email, mac, first, last, count, vlan_id, rule, ap) VALUES (?, ?, ?, ?, 1, ?, ?, ?)
      ON CONFLICT(email, mac) DO UPDATE SET last = excluded.last, count = count + 1,
        vlan_id = excluded.vlan_id, rule = excluded.rule, ap = excluded.ap`).run(email, m, now, now, vlanId, rule, ap);
    return !prev || prev.last < startOfDay(now);
  }

  function counts(since) {
    const ev = q(`SELECT SUM(category = 'denied') AS denied, SUM(category = 'error') AS errors FROM events WHERE time >= ?`).get(since);
    const lg = q('SELECT COUNT(DISTINCT email) AS people, COUNT(*) AS devices FROM logins WHERE last >= ?').get(since);
    return { people: lg.people ?? 0, devices: lg.devices ?? 0, denied: ev.denied ?? 0, errors: ev.errors ?? 0 };
  }

  const countSince = (category, since) =>
    q('SELECT COUNT(*) AS n FROM events WHERE category = ? AND time >= ?').get(category, since).n;

  const recentLogins = (limit = 25) => q('SELECT * FROM logins ORDER BY last DESC LIMIT ?').all(limit);

  /** Who last logged in from a device, for accounting that only names the device. */
  const lastLoginByMac = (mac) => q('SELECT email FROM logins WHERE mac = ? ORDER BY last DESC LIMIT 1').get(normalizeMac(mac))?.email ?? null;

  /**
   * Applies one accounting report. Counters are per session and only grow, so the
   * change since the previous report is added to that day's usage. A counter that went
   * backwards (the session was restarted under the same id) counts from zero.
   */
  function recordAccounting({ status, sessionId, who, mac, ip, ap, nas, down, up, seconds, cause }, now = Date.now()) {
    if (status === 'Accounting-On' || status === 'Accounting-Off') {
      // The access point or controller restarted: its open sessions are over.
      q("UPDATE sessions SET stopped = ?, cause = 'NAS restart' WHERE nas = ? AND stopped IS NULL").run(now, nas ?? '');
      return null;
    }
    const m = normalizeMac(mac) ?? 'unknown';
    const id = `${nas ?? ''}|${sessionId ?? ''}|${m}`;
    let prev = q('SELECT * FROM sessions WHERE id = ?').get(id);
    if (!prev) {
      const started = seconds ? now - seconds * 1000 : now;
      q('INSERT INTO sessions (id, who, mac, started, updated) VALUES (?, ?, ?, ?, ?)').run(id, who, m, started, now);
      prev = { bytes_down: 0, bytes_up: 0 };
    }
    const dDown = down >= prev.bytes_down ? down - prev.bytes_down : down;
    const dUp = up >= prev.bytes_up ? up - prev.bytes_up : up;
    q(`UPDATE sessions SET who = ?, ip = COALESCE(?, ip), ap = COALESCE(?, ap), nas = ?, updated = ?, bytes_down = ?, bytes_up = ?,
      seconds = COALESCE(?, seconds), stopped = ?, cause = ? WHERE id = ?`).run(
      who, ip ?? null, ap ?? null, nas ?? null, now, down, up, seconds ?? null, status === 'Stop' ? now : null, cause ?? null, id,
    );
    if (dDown || dUp) {
      q(`INSERT INTO usage_daily (day, who, mac, bytes_down, bytes_up) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(day, who, mac) DO UPDATE SET bytes_down = bytes_down + excluded.bytes_down, bytes_up = bytes_up + excluded.bytes_up`).run(
        dayOf(now), who, m, dDown, dUp,
      );
    }
    return usageOn(who, dayOf(now));
  }

  function usageOn(who, day) {
    const r = q('SELECT COALESCE(SUM(bytes_down), 0) AS down, COALESCE(SUM(bytes_up), 0) AS up FROM usage_daily WHERE who = ? AND day = ?').get(who, day);
    return { down: r.down, up: r.up, total: r.down + r.up };
  }

  /** Sessions still open and reported recently (a device that vanished without a Stop drops off). */
  const onlineNow = (now = Date.now(), staleMs = 30 * 60_000) =>
    q(`SELECT s.*, l.vlan_id FROM sessions s LEFT JOIN logins l ON l.email = s.who AND l.mac = s.mac
      WHERE s.stopped IS NULL AND s.updated > ? ORDER BY s.started DESC LIMIT 1000`).all(now - staleMs);

  /** Totals, per VLAN and the top users between two days (inclusive). */
  function usageReport(fromDay, toDay, limit = 50) {
    const totals = q(`SELECT COALESCE(SUM(bytes_down), 0) AS down, COALESCE(SUM(bytes_up), 0) AS up, COUNT(DISTINCT who) AS people
      FROM usage_daily WHERE day BETWEEN ? AND ?`).get(fromDay, toDay);
    const byVlan = q(`SELECT l.vlan_id AS vlan_id, SUM(u.bytes_down) AS down, SUM(u.bytes_up) AS up, COUNT(DISTINCT u.who) AS people
      FROM usage_daily u LEFT JOIN logins l ON l.email = u.who AND l.mac = u.mac
      WHERE u.day BETWEEN ? AND ? GROUP BY l.vlan_id ORDER BY SUM(u.bytes_down + u.bytes_up) DESC`).all(fromDay, toDay);
    const top = q(`SELECT who, SUM(bytes_down) AS down, SUM(bytes_up) AS up, COUNT(DISTINCT mac) AS devices
      FROM usage_daily WHERE day BETWEEN ? AND ? GROUP BY who ORDER BY SUM(bytes_down + bytes_up) DESC LIMIT ?`).all(fromDay, toDay, limit);
    return { totals, byVlan, top };
  }

  function personUsage(who, fromDay) {
    return {
      daily: q(`SELECT day, SUM(bytes_down) AS down, SUM(bytes_up) AS up FROM usage_daily WHERE who = ? AND day >= ?
        GROUP BY day ORDER BY day DESC`).all(who, fromDay),
      devices: q(`SELECT mac, SUM(bytes_down) AS down, SUM(bytes_up) AS up FROM usage_daily WHERE who = ? AND day >= ?
        GROUP BY mac ORDER BY SUM(bytes_down + bytes_up) DESC`).all(who, fromDay),
      sessions: q('SELECT * FROM sessions WHERE who = ? ORDER BY started DESC LIMIT 30').all(who),
    };
  }

  const usageRows = (fromDay) => q('SELECT * FROM usage_daily WHERE day >= ? ORDER BY day DESC, who').all(fromDay);

  /** Whether an event of this type was already recorded for this person today. */
  const hadEventToday = (type, email, now = Date.now()) =>
    Boolean(q('SELECT 1 FROM events WHERE type = ? AND email = ? AND time >= ? LIMIT 1').get(type, email, startOfDay(now)));

  function events({ category = null, q: search = null, email = null, before = null, limit = 50 } = {}) {
    const like = search ? `%${search.toLowerCase()}%` : null;
    return q(`SELECT * FROM events
      WHERE (? IS NULL OR category = ?)
        AND (? IS NULL OR email = ?)
        AND (? IS NULL OR id < ?)
        AND (? IS NULL OR email LIKE ? OR mac LIKE ? OR type LIKE ? OR lower(detail) LIKE ?)
      ORDER BY id DESC LIMIT ?`)
      .all(category, category, email, email, before, before, like, like, like, like, like, Math.min(limit, 200))
      .map(parse);
  }

  /** Everyone who has logged in or been turned away. */
  function people({ q: search = null, limit = 100 } = {}) {
    const like = search ? `%${search.toLowerCase()}%` : null;
    return q(`WITH everyone AS (
        SELECT email, last AS time FROM logins
        UNION ALL SELECT email, time FROM events WHERE email IS NOT NULL AND category IN ('signin', 'denied')
      )
      SELECT p.email,
        MAX(p.time) AS last,
        (SELECT COUNT(*) FROM logins l WHERE l.email = p.email) AS devices,
        (SELECT COALESCE(SUM(count), 0) FROM logins l WHERE l.email = p.email) AS logins,
        (SELECT COUNT(*) FROM events e WHERE e.email = p.email AND e.category = 'denied') AS denied,
        EXISTS (SELECT 1 FROM blocked b WHERE b.email = p.email) AS blocked
      FROM everyone p
      WHERE (? IS NULL OR p.email LIKE ? OR EXISTS (SELECT 1 FROM logins l WHERE l.email = p.email AND l.mac LIKE ?))
      GROUP BY p.email ORDER BY last DESC LIMIT ?`).all(like, like, like, Math.min(limit, 500));
  }

  function person(email) {
    const e = email.toLowerCase();
    return {
      email: e,
      blocked: q('SELECT * FROM blocked WHERE email = ?').get(e) ?? null,
      devices: q('SELECT * FROM logins WHERE email = ? ORDER BY last DESC').all(e),
      events: events({ email: e, limit: 100 }),
    };
  }

  const isBlocked = (email) => Boolean(q('SELECT 1 FROM blocked WHERE email = ?').get(String(email).toLowerCase()));
  const block = (email, reason, by, now = Date.now()) =>
    q(`INSERT INTO blocked (email, reason, blocked_by, at) VALUES (?, ?, ?, ?)
      ON CONFLICT(email) DO UPDATE SET reason = excluded.reason, blocked_by = excluded.blocked_by, at = excluded.at`).run(
      email.toLowerCase(),
      reason || null,
      by,
      now,
    );
  const unblock = (email) => q('DELETE FROM blocked WHERE email = ?').run(email.toLowerCase());
  const blockedList = () => q('SELECT * FROM blocked ORDER BY at DESC').all();

  function getSetting(key) {
    const row = q('SELECT value FROM settings WHERE key = ?').get(key);
    return row ? JSON.parse(row.value) : undefined;
  }
  function setSetting(key, value) {
    if (value === undefined) return q('DELETE FROM settings WHERE key = ?').run(key);
    q('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(
      key,
      JSON.stringify(value),
    );
  }

  const addKey = ({ id, email, label, vlanId, rule, kind, expires = null, createdBy = null, created = Date.now() }) =>
    q(`INSERT INTO wifi_keys (id, email, label, vlan_id, rule, created, kind, expires, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, email.toLowerCase(), label || null, vlanId ?? null, rule ?? null, created, kind, expires, createdBy);
  const getKeyRow = (id) => q('SELECT * FROM wifi_keys WHERE id = ?').get(id);
  const keysOfKind = (kind) => q('SELECT * FROM wifi_keys WHERE kind = ? ORDER BY created DESC').all(kind);
  const allKeys = () => q('SELECT * FROM wifi_keys ORDER BY created DESC').all();
  const expiredGuests = (now = Date.now()) => q("SELECT * FROM wifi_keys WHERE kind = 'guest' AND expires <= ?").all(now);
  const removeKey = (id) => q('DELETE FROM wifi_keys WHERE id = ?').run(id);
  const setKeyMac = (id, mac) => q('UPDATE wifi_keys SET mac = ? WHERE id = ?').run(normalizeMac(mac), id);
  const replaceKey = (oldId, newId) => q('UPDATE wifi_keys SET id = ? WHERE id = ?').run(newId, oldId);
  function keyCounts() {
    const row = q("SELECT COUNT(*) AS guests FROM wifi_keys WHERE kind = 'guest'").get();
    return { guests: row.guests };
  }

  /** Writes a consistent copy of the database into dir and keeps the newest `keep` copies. */
  function backup(dir, keep = 14, now = new Date()) {
    fs.mkdirSync(dir, { recursive: true });
    const stamp = now.toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const target = path.join(dir, `wifi-portal-${stamp}.db`);
    db.exec(`VACUUM INTO '${target.replace(/'/g, "''")}'`);
    const old = fs.readdirSync(dir).filter((f) => /^wifi-portal-[\d-]+\.db$/.test(f)).sort().reverse().slice(keep);
    for (const f of old) fs.rmSync(path.join(dir, f));
    return { file: target, size: fs.statSync(target).size, removed: old.length };
  }

  /** Removes events and device records older than the retention period. */
  function purge(retentionDays, now = Date.now()) {
    const cutoff = now - retentionDays * 86_400_000;
    const ev = q('DELETE FROM events WHERE time < ?').run(cutoff);
    const lg = q('DELETE FROM logins WHERE last < ?').run(cutoff);
    const se = q('DELETE FROM sessions WHERE updated < ?').run(cutoff);
    const us = q('DELETE FROM usage_daily WHERE day < ?').run(dayOf(cutoff));
    return { events: Number(ev.changes), logins: Number(lg.changes), sessions: Number(se.changes), usage: Number(us.changes) };
  }

  return {
    record,
    recordLogin,
    counts,
    countSince,
    recentLogins,
    lastLoginByMac,
    recordAccounting,
    usageOn,
    onlineNow,
    usageReport,
    personUsage,
    usageRows,
    hadEventToday,
    events,
    people,
    person,
    isBlocked,
    block,
    unblock,
    blockedList,
    getSetting,
    setSetting,
    addKey,
    getKeyRow,
    keysOfKind,
    allKeys,
    expiredGuests,
    removeKey,
    setKeyMac,
    replaceKey,
    keyCounts,
    backup,
    purge,
    close: () => db.close(),
  };
}
