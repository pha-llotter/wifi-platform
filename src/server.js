import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { createAccess } from './access.js';
import { createAdmin } from './admin.js';
import { createAlerts } from './alerts.js';
import { createApp } from './app.js';
import { createChecks } from './checks.js';
import { loadConfig } from './config.js';
import { openDb } from './db.js';
import { createDirectoryClient, createDriveBackup, createMailer, createServiceAccount } from './google.js';
import { createKeyService } from './keys.js';
import { createLogger } from './log.js';
import { createRadiusApi } from './radius-api.js';
import { createSettings } from './settings.js';
import { createVszClient } from './vsz.js';

const config = loadConfig(process.argv[2]);
const fileLog = createLogger(config.logFile);
const db = openDb(config.database);
const settings = createSettings({ config, db });
const dir = config.google.directory;

const serviceAccount = dir?.serviceAccountKeyFile ? createServiceAccount(dir) : null;
const directory = dir?.enabled ? createDirectoryClient({ serviceAccount, adminEmail: dir.adminEmail }) : null;
const mailer = config.alerts.from ? createMailer({ serviceAccount, from: config.alerts.from }) : null;

// Everything that is logged also lands in the database the dashboard reads from, and
// anything IT should hear about goes out by email.
let alerts = null;
const log = (event, data = {}) => {
  fileLog(event, data);
  try {
    db.record(event, data);
  } catch (err) {
    fileLog('db_error', { event, error: err.message });
  }
  if (event !== 'alert_sent' && event !== 'alert_error') alerts?.onEvent(event, data);
};
alerts = createAlerts({ mailer, to: config.alerts.to, publicUrl: config.publicUrl, log });

const access = createAccess({ settings, directory });
const radiusApi = createRadiusApi({ config, db, access, settings, log });

const drive = config.backup.drive ? createDriveBackup({ serviceAccount, ...config.backup.drive }) : null;

// Copies the latest backup to Drive in the background; the local copy is already safe.
function offsite(backup) {
  backup.offsite = { pending: true };
  drive
    .upload(backup.file)
    .then((r) => {
      backup.offsite = { at: Date.now(), name: r.name, size: r.size };
      log('backup_offsite', { name: r.name, size: r.size, removed: r.removed });
    })
    .catch((err) => {
      backup.offsite = { at: Date.now(), error: err.message };
      log('backup_error', { error: `Drive copy: ${err.message}` });
    });
}

let lastBackup = null;
function backupNow() {
  try {
    const result = db.backup(config.backup.dir, config.backup.keep);
    lastBackup = { at: Date.now(), file: result.file, size: result.size };
    log('backup', { file: result.file, size: result.size, removed: result.removed });
    if (drive) offsite(lastBackup);
    return lastBackup;
  } catch (err) {
    lastBackup = { at: Date.now(), error: err.message };
    log('backup_error', { error: err.message });
    throw err;
  }
}
const platform = { backupNow, status: () => ({ backup: lastBackup, alerts: alerts.status, radius: radiusApi.status() }) };

const vsz = createVszClient(config.dpsk);
const keys = createKeyService({ config, db, vsz, log });
platform.checks = createChecks({ config, directory, mailer, vsz, drive, radiusStatus: radiusApi.status });
const admin = createAdmin({ config, db, settings, keys, access, platform, log });
const app = createApp({ admin, radiusApi, log });

const listen = (server, port, host) =>
  new Promise((resolve, reject) => server.once('error', reject).listen(port, host, () => resolve(server)));

const servers = [];
if (config.https) {
  const tls = { cert: fs.readFileSync(config.https.cert), key: fs.readFileSync(config.https.key) };
  servers.push(await listen(https.createServer(tls, app.handle), config.https.port));
  const toHttps = http.createServer((req, res) => {
    res.writeHead(301, { Location: `${config.publicUrl}${req.url}`, 'Cache-Control': 'no-store' });
    res.end();
  });
  servers.push(await listen(toHttps, config.http.port));
} else {
  servers.push(await listen(http.createServer(app.handle), config.http.port, config.http.host));
}

const timers = [];
const every = (ms, fn) => {
  const t = setInterval(fn, ms);
  t.unref();
  timers.push(t);
};
const soon = (ms, fn) => setTimeout(fn, ms).unref();

const purge = () => {
  const removed = db.purge(settings.current().retentionDays);
  if (removed.events || removed.logins) fileLog('purged', removed);
};
purge();
every(6 * 3600_000, purge);

// Guest SSID keys: end guest keys on time and notice keys changed on the vSZ.
const sync = () => keys.sync().catch((err) => log('key_sync_error', { error: err.message }));
soon(10_000, sync);
every(config.dpsk.syncHours * 3600_000, sync);
every(15 * 60_000, () => keys.expireGuests().catch((err) => log('key_sync_error', { error: err.message })));

const tryBackup = () => {
  try {
    backupNow();
  } catch {}
};
soon(60_000, tryBackup);
every(24 * 3600_000, tryBackup);

if (vsz.health.security === 'unverified') {
  fileLog('vsz_tls_warning', { warning: 'The vSZ certificate is not checked. Set dpsk.tlsFingerprint (npm run vsz:fingerprint).' });
}

log('started', {
  publicUrl: config.publicUrl,
  http: config.http.port,
  https: config.https?.port ?? null,
  schoolSsid: config.radius.ssid,
  guestSsid: config.dpsk.ssid,
  vszSecurity: vsz.health.security,
  directory: Boolean(directory),
  alerts: alerts.status.enabled,
  admins: config.admin.emails.length,
});

function shutdown() {
  log('stopping');
  for (const t of timers) clearInterval(t);
  vsz.close();
  radiusApi.close();
  admin.close();
  for (const s of servers) s.close();
  db.close();
  fileLog.close();
  setTimeout(() => process.exit(0), 500).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
