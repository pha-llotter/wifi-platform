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
  c.radius = { ssid: 'Nexus', defaultDomain: c.google.allowedDomains[0] ?? null, serverName: `radius.${c.google.allowedDomains[0] ?? 'example.org'}`, sessionTimeout: 43200, apiAllowFrom: ['127.0.0.1', '::1'], fallbackVlan: null, accountingStaleMinutes: 30, ...c.radius };
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

  // The school networks: open Hotspot (WISPr) WLANs whose sign-in page is this platform.
  // networks maps each SSID to the VLAN its WLAN puts devices on; a person may only sign
  // in on a network whose VLAN matches their rule. Signed-in devices are remembered for
  // rememberDays and reconnect without the page (MAC authentication on the WLAN).
  c.portal = { rememberDays: 90, ...c.portal };
  const nets = c.portal.networks;
  need(nets && typeof nets === 'object' && Object.keys(nets).length > 0,
    'portal.networks must list each sign-in network and its VLAN, e.g. {"Nexus": 10, "Nexus Staff": 1}');
  for (const [ssid, vlan] of Object.entries(nets ?? {})) {
    need(Number.isInteger(vlan) && vlan >= 1 && vlan <= 4094, `portal.networks["${ssid}"] must be the VLAN number of that network (1 to 4094)`);
  }
  need(Number.isInteger(c.portal.rememberDays) && c.portal.rememberDays >= 0 && c.portal.rememberDays <= 365,
    'portal.rememberDays must be from 0 (sign in every time) to 365');
  c.portal.nbi = { port: 9443, protocol: 'https', tlsVerify: false, tlsFingerprint: null, ...c.portal.nbi };
  need(c.portal.nbi.host, 'portal.nbi.host is the address the platform reaches the vSZ portal interface (NBI) on');
  need(c.portal.nbi.password, 'portal.nbi.password is the WISPr Northbound Interface password set on the vSZ');
  need(!c.portal.nbi.tlsFingerprint || /^([0-9a-f]{2}:?){32}$/i.test(c.portal.nbi.tlsFingerprint),
    'portal.nbi.tlsFingerprint must be a SHA-256 fingerprint (run scripts/vsz-fingerprint.js against the NBI port)');
  need(c.portal.nbi.protocol !== 'https' || c.portal.nbi.tlsFingerprint || c.portal.nbi.tlsVerify === true,
    'portal.nbi.tlsFingerprint is required so the vSZ certificate is checked before the NBI password is sent');

  // Google Secure LDAP checks the passwords typed on the sign-in page.
  c.google.ldap = {
    host: 'ldap.google.com',
    port: 636,
    clientCert: '/etc/wifi-portal/google-ldap/ldap-client.crt',
    clientKey: '/etc/wifi-portal/google-ldap/ldap-client.key',
    baseDn: c.google.allowedDomains[0] ? c.google.allowedDomains[0].split('.').map((p) => `dc=${p}`).join(',') : '',
    identity: '',
    password: '',
    ...c.google.ldap,
  };

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
  // Sites visited per person, from the school firewall's syslog (browsing.js). Off by default.
  c.browsing = { enabled: false, allowFrom: [], retentionDays: 30, vlans: [], viewers: [], ...c.browsing };
  c.browsing.listen = { host: '0.0.0.0', port: 5514, ...c.browsing.listen };
  if (c.browsing.enabled) {
    need(Array.isArray(c.browsing.allowFrom) && c.browsing.allowFrom.length > 0,
      "browsing.allowFrom must list the address the firewall's logs come from (the school's public IP), so no one else can send fake ones");
    need(Number.isInteger(c.browsing.listen.port) && c.browsing.listen.port >= 0 && c.browsing.listen.port < 65536,
      'browsing.listen.port must be a port number, e.g. 5514');
    need(Number.isInteger(c.browsing.retentionDays) && c.browsing.retentionDays >= 1 && c.browsing.retentionDays <= 365,
      'browsing.retentionDays must be from 1 to 365');
    need(Array.isArray(c.browsing.vlans) && c.browsing.vlans.every((v) => Number.isInteger(v)),
      'browsing.vlans must be a list of VLAN numbers to record, e.g. [10] for learners only, or [] for everyone');
    need(Array.isArray(c.browsing.viewers), 'browsing.viewers must be a list of admin emails, or [] for every admin');
  }
  c.browsing.viewers = (Array.isArray(c.browsing.viewers) ? c.browsing.viewers : []).map((e) => String(e).toLowerCase());

  c.database ??= 'data/wifi-portal.db';
  c.backup.dir ??= path.join(path.dirname(path.resolve(c.database)), 'backups');
  c.retentionDays ??= 90;

  c.branding = { name: 'WiFi', color: '#1a56db', school: '', motto: '', ...c.branding };
  c.logFile ??= null;

  if (problems.length) throw new Error(`Invalid config:\n  - ${problems.join('\n  - ')}`);
  return c;
}
