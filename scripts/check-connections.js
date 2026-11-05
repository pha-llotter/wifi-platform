// Tries each outside service the platform depends on: the Google directory, Google
// Secure LDAP, alert email (sends a test), Drive backups, the vSZ API and the vSZ portal interface (NBI). Same as Settings → Check.
//   docker compose exec wifi-portal node scripts/check-connections.js /etc/wifi-portal/config.json
//   add --no-email to skip the test alert email
import { createChecks } from '../src/checks.js';
import { loadConfig } from '../src/config.js';
import { createDirectoryClient, createDriveBackup, createMailer, createServiceAccount } from '../src/google.js';
import { createNbiClient } from '../src/nbi.js';
import { createVszClient } from '../src/vsz.js';

const args = process.argv.slice(2);
const config = loadConfig(args.find((a) => !a.startsWith('--')));
const dir = config.google.directory;

let serviceAccount = null;
try {
  serviceAccount = dir?.serviceAccountKeyFile ? createServiceAccount(dir) : null;
} catch (err) {
  console.error(`✖ Can't read the service account key ${dir.serviceAccountKeyFile}: ${err.message}`);
  process.exit(1);
}
const directory = dir?.enabled ? createDirectoryClient({ serviceAccount, adminEmail: dir.adminEmail }) : null;
const mailer = config.alerts.from ? createMailer({ serviceAccount, from: config.alerts.from }) : null;
const drive = config.backup.drive ? createDriveBackup({ serviceAccount, ...config.backup.drive }) : null;
const vsz = createVszClient(config.dpsk);

const nbi = createNbiClient(config.portal.nbi);
const checks = createChecks({ config, directory, mailer, vsz, nbi, drive });
try {
  const results = (await checks.run({ email: !args.includes('--no-email') })).filter((r) => r.name !== 'FreeRADIUS');
  for (const r of results) console.log(`${r.ok === true ? '✔' : r.ok === false ? '✖' : '–'} ${r.name}\n    ${r.detail}`);
  process.exitCode = results.some((r) => r.ok === false) ? 1 : 0;
} finally {
  await vsz.close();
}
