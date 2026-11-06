// Visitor keys (Ruckus DPSK) on the guest SSID: made by an admin, each with an end
// date. The vSZ binds each key to the first device that uses it.
export class KeyError extends Error {}

/**
 * A guest key's user name on the vSZ, which allows only A-Z a-z 0-9 - _ . @ # $ and
 * 2 to 64 characters: "guest#Mrs_Botha#it@school.org". "#" never appears inside the
 * parts, so the name and the email can be read back (guestFromVszName).
 */
export function vszGuestName(name, by) {
  const clean = (s) => String(s ?? '')
    .normalize('NFD').replace(/[̀-ͯ]/g, '') // Zoë → Zoe
    .replace(/[^A-Za-z0-9\-_.@$]+/g, '_')
    .replace(/^_+|_+$/g, '');
  const email = clean(by).slice(0, 40);
  const room = 64 - 'guest##'.length - email.length;
  const label = clean(name).slice(0, room).replace(/_+$/, '') || 'visitor';
  return `guest#${label}#${email}`;
}

/**
 * { label, email } from a guest key's vSZ user name, or null when it isn't one. Reads
 * both the current form and the older "guest: Mrs Botha (it@school.org)".
 */
export function guestFromVszName(userName) {
  const raw = String(userName ?? '').trim();
  const old = raw.match(/^guest: (.+?) \((.+)\)$/i);
  if (old) return { label: old[1], email: old[2] };
  const now = raw.match(/^guest#([^#]+)#([^#]*)$/i);
  if (now) return { label: now[1].replace(/_/g, ' '), email: now[2] };
  return null;
}

/** How a guest key is shown in usage and Activity: "guest: Mrs Botha (it@school.org)". */
export const guestDisplayName = ({ label, email }) => `guest: ${label} (${email})`;

export function createKeyService({ config, db, vsz, log }) {
  let lastSync = null;
  let syncing = null;
  const cfg = config.dpsk;

  async function create(row, vszUserName) {
    const key = await vsz.createKey({ userName: vszUserName, vlanId: row.vlanId });
    db.addKey({ ...row, id: key.id });
    return { ...db.getKeyRow(key.id), passphrase: key.passphrase };
  }

  /** A visitor's key on the guest VLAN that is removed once `days` have passed. */
  async function issueGuest({ name, days }, { by }) {
    const d = Number(days);
    if (!Number.isInteger(d) || d < 1 || d > cfg.maxGuestDays) throw new KeyError(`Guest keys can last from 1 to ${cfg.maxGuestDays} days.`);
    const guestName = String(name ?? '').trim().slice(0, 40);
    if (!guestName) throw new KeyError("Enter the guest's name.");
    const expires = Date.now() + d * 86_400_000;
    const key = await create(
      { email: by, label: guestName, vlanId: cfg.guestVlanId, rule: 'Guest', kind: 'guest', expires, createdBy: by },
      vszGuestName(guestName, by),
    );
    log('key_issued', { label: guestName, kind: 'guest', vlanId: cfg.guestVlanId, expires, by });
    return key;
  }

  /** The passphrase, fetched from the vSZ (never stored here). */
  async function reveal(id) {
    const row = db.getKeyRow(id);
    if (!row) return null;
    const key = await vsz.getKey(id);
    if (!key) {
      db.removeKey(id);
      log('key_missing', { label: row.label, reason: 'deleted on the vSZ' });
      return null;
    }
    if (key.macAddress && key.macAddress !== row.mac) db.setKeyMac(id, key.macAddress);
    return { ...db.getKeyRow(id), passphrase: key.passphrase };
  }

  /** Frees a key from the device it was bound to, keeping the passphrase. */
  async function reset(id, { by }) {
    const row = db.getKeyRow(id);
    if (!row) return null;
    const remote = await vsz.getKey(id);
    if (!remote) {
      db.removeKey(id);
      return null;
    }
    await vsz.deleteKeys([id]);
    const fresh = await vsz.createKey({ userName: remote.userName, vlanId: row.vlan_id, passphrase: remote.passphrase });
    db.replaceKey(id, fresh.id);
    db.setKeyMac(fresh.id, null);
    log('key_reset', { label: row.label, kind: row.kind, mac: row.mac, by });
    return { ...db.getKeyRow(fresh.id), passphrase: remote.passphrase };
  }

  async function revoke(id, { by, reason }) {
    const row = db.getKeyRow(id);
    if (!row) return false;
    await vsz.deleteKeys([id]);
    db.removeKey(id);
    log('key_revoked', { label: row.label, kind: row.kind, mac: row.mac, by, reason });
    return true;
  }

  async function expireGuests() {
    const rows = db.expiredGuests();
    if (!rows.length) return 0;
    await vsz.deleteKeys(rows.map((r) => r.id));
    for (const row of rows) {
      db.removeKey(row.id);
      log('key_revoked', { label: row.label, kind: 'guest', reason: 'guest key ended', by: 'platform' });
    }
    return rows.length;
  }

  /**
   * Takes over guest keys that exist on the vSZ but not here, e.g. after restoring an
   * old backup. They come back as guests that end within a day.
   */
  async function adopt({ by }) {
    const known = new Set(db.allKeys().map((r) => r.id));
    let adopted = 0;
    let skipped = 0;
    for (const key of await vsz.listKeys()) {
      if (known.has(key.id)) continue;
      const guest = guestFromVszName(key.userName);
      if (guest) {
        db.addKey({ id: key.id, email: guest.email, label: guest.label, vlanId: key.vlanId ?? null, rule: 'Guest', kind: 'guest', expires: Date.now() + 86_400_000, createdBy: by });
      } else {
        skipped++;
        continue;
      }
      if (key.macAddress) db.setKeyMac(key.id, key.macAddress);
      adopted++;
    }
    log('keys_adopted', { adopted, skipped, by });
    return { adopted, skipped };
  }

  /** Ends expired guest keys and notices keys deleted on the vSZ or newly bound to a device. */
  async function runSync(by) {
    const started = Date.now();
    const summary = { expired: await expireGuests(), missing: 0, checked: 0 };
    const remote = new Map((await vsz.listKeys()).map((k) => [k.id, k]));
    for (const row of db.allKeys()) {
      summary.checked++;
      const key = remote.get(row.id);
      if (!key) {
        db.removeKey(row.id);
        summary.missing++;
        log('key_missing', { label: row.label, kind: row.kind, reason: 'deleted on the vSZ' });
      } else if (key.macAddress && key.macAddress !== row.mac) {
        db.setKeyMac(row.id, key.macAddress);
      }
    }
    lastSync = { ...summary, at: Date.now(), ms: Date.now() - started, by };
    log('key_sync', lastSync);
    return lastSync;
  }

  function sync({ by = 'scheduled sync' } = {}) {
    syncing ??= runSync(by).finally(() => (syncing = null));
    return syncing;
  }

  return { issueGuest, reveal, reset, revoke, expireGuests, adopt, sync, status: () => ({ vsz: vsz.health, lastSync, syncing: Boolean(syncing) }) };
}
