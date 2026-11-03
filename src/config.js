import fs from 'node:fs';
import path from 'node:path';
import { validatePolicy } from './policy.js';

export function loadConfig(file = process.env.WIFI_PORTAL_CONFIG || 'config.json') {
  const full = path.resolve(file);
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(full, 'utf8'));
  } catch (err) {
    throw new Error(`Could not read config ${full}: ${err.message}`);
  }
  return normalizeConfig(raw);
}

export function normalizeConfig(raw) {
  const problems = [];
  const need = (ok, msg) => ok || problems.push(msg);
  const c = structuredClone(raw);

  need(/^https?:\/\/[^/]+/.test(c.publicUrl ?? ''), 'publicUrl must be the portal address, e.g. https://wifi.example.org');
  c.publicUrl = String(c.publicUrl ?? '').replace(/\/+$/, '');

  c.http = { port: 80, ...c.http };
  if (c.https) {
    need(c.https.cert && c.https.key, 'https.cert and https.key must point at the TLS certificate and key');
    c.https = { port: 443, ...c.https };
  }
  c.trustProxy = Boolean(c.trustProxy);

  c.google ??= {};
  need(c.google.clientId, 'google.clientId is required');
  need(c.google.clientSecret, 'google.clientSecret is required');
  need(Array.isArray(c.google.allowedDomains) && c.google.allowedDomains.length > 0,
    'google.allowedDomains must list at least one Workspace domain');
  c.google.allowedDomains = (c.google.allowedDomains ?? []).map((d) => String(d).toLowerCase());
  const dir = c.google.directory;
  if (dir?.enabled) {
    need(dir.serviceAccountKeyFile, 'google.directory.serviceAccountKeyFile is required when the directory is enabled');
    need(dir.adminEmail, 'google.directory.adminEmail is required when the directory is enabled');
  }

  // The school SSID: 802.1X logins, checked by FreeRADIUS against Google Secure LDAP.
  // FreeRADIUS asks the platform for each person's VLAN over this local API.
  c.radius = { ssid: 'PHA-WiFi', defaultDomain: c.google.allowedDomains[0] ?? null, serverName: `radius.${c.google.allowedDomains[0] ?? 'example.org'}`, sessionTimeout: 43200, apiAllowFrom: ['127.0.0.1', '::1'], fallbackVlan: null, accountingStaleMinutes: 30, ...c.radius };
  need(typeof c.radius.apiToken === 'string' && c.radius.apiToken.length >= 24,
    'radius.apiToken must be a random string of 24+ characters, the same one FreeRADIUS uses (PLATFORM_TOKEN)');
  need(Number.isInteger(c.radius.sessionTimeout) && c.radius.sessionTimeout >= 600,
    'radius.sessionTimeout must be at least 600 seconds; devices log in again after it');
  need(Array.isArray(c.radius.apiAllowFrom), 'radius.apiAllowFrom must be a list of addresses FreeRADIUS calls from');

  // The guest SSID: visitor keys (DPSK) with end dates, managed through the vSZ public API.
  c.dpsk = {
    port: 8443,
    protocol: 'https',
    apiVersion: 'v9_1',
    tlsVerify: false,
    tlsFingerprint: null,
    syncHours: 6,
    guestVlanId: null,
    maxGuestDays: 30,
    ...c.dpsk,
  };
  for (const k of ['host', 'username', 'password', 'zoneId', 'wlanId', 'ssid']) {
    need(c.dpsk[k], `dpsk.${k} is required (run "npm run vsz:wlans" to find the zone and WLAN ids)`);
  }
  need(c.dpsk.guestVlanId == null || (Number.isInteger(c.dpsk.guestVlanId) && c.dpsk.guestVlanId >= 1 && c.dpsk.guestVlanId <= 4094),
    'dpsk.guestVlanId must be a VLAN number from 1 to 4094');
  need(!c.dpsk.tlsFingerprint || /^([0-9a-f]{2}:?){32}$/i.test(c.dpsk.tlsFingerprint),
    'dpsk.tlsFingerprint must be the SHA-256 fingerprint (run "npm run vsz:fingerprint" to read it)');
  // The vSZ API password crosses the internet: never send it to an unchecked certificate.
  need(c.dpsk.protocol !== 'https' || c.dpsk.tlsFingerprint || c.dpsk.tlsVerify === true,
    'dpsk.tlsFingerprint is required so the vSZ certificate is checked (run "npm run vsz:fingerprint" and compare it with the vSZ web console)');

  // Data used per person comes from the vSZ's RADIUS accounting. alertGb: email IT
  // when someone passes this much in a day (null = off; also editable in the dashboard).
  c.usage = { alertGb: null, ...c.usage };

  // Daily copies of the database, kept next to it unless dir says otherwise.
  c.backup = { keep: 14, ...c.backup };

  // Email to IT when something needs attention, sent through Gmail as alerts.from
  // (a Workspace mailbox) with the same service account as the directory lookup.
  c.alerts = { to: [], from: null, ...c.alerts };
  if (c.alerts.from || c.alerts.to.length) {
    need(Array.isArray(c.alerts.to) && c.alerts.to.length > 0, 'alerts.to must list who gets alert emails');
    need(c.alerts.from, 'alerts.from must be the Workspace mailbox alerts are sent from');
    need(dir?.serviceAccountKeyFile, 'alerts need google.directory.serviceAccountKeyFile (the same service account)');
  }

  // Off-site: each nightly copy also goes to a Google Drive folder, uploaded as a
  // Workspace user (backup.drive.as) who may add files there.
  if (c.backup.drive) {
    c.backup.drive = { keep: 30, as: c.alerts.from ?? dir?.adminEmail ?? null, ...c.backup.drive };
    need(c.backup.drive.folderId, 'backup.drive.folderId is the Drive folder for off-site backups (the last part of its URL)');
    need(c.backup.drive.as, 'backup.drive.as must be a Workspace user who can add files to that folder');
    need(dir?.serviceAccountKeyFile, 'Drive backups need google.directory.serviceAccountKeyFile (the same service account)');
  }

  const checked = validatePolicy(c.policy ?? {}, { directoryEnabled: Boolean(dir?.enabled) });
  problems.push(...checked.problems.map((p) => `policy: ${p}`));
  c.policy = checked.policy;

  c.admin = { emails: [], allowFrom: [], ...c.admin };
  c.admin.emails = c.admin.emails.map((e) => String(e).toLowerCase());
  need(Array.isArray(c.admin.allowFrom), 'admin.allowFrom must be a list of IP addresses or CIDR ranges');
  c.database ??= 'data/wifi-portal.db';
  c.backup.dir ??= path.join(path.dirname(path.resolve(c.database)), 'backups');
  c.retentionDays ??= 90;

  c.branding = { name: 'WiFi', color: '#1a56db', school: '', motto: '', ...c.branding };
  c.logFile ??= null;

  if (problems.length) throw new Error(`Invalid config:\n  - ${problems.join('\n  - ')}`);
  return c;
}
