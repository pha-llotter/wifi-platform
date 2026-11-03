// Shows the SHA-256 fingerprint of the certificate the vSZ presents on its API port,
// to put in dpsk.tlsFingerprint so the platform only ever talks to that vSZ.
//   node scripts/vsz-fingerprint.js /etc/wifi-portal/config.json
// Compare it with the certificate shown in the vSZ web interface (or run this from the
// school network) before trusting it.
import fs from 'node:fs';
import { fetchFingerprint } from '../src/vsz.js';

const file = process.argv[2] ?? process.env.WIFI_PORTAL_CONFIG ?? 'config.json';
const { dpsk = {} } = JSON.parse(fs.readFileSync(file, 'utf8'));
if (!dpsk.host) {
  console.error(`Set dpsk.host in ${file} first.`);
  process.exit(1);
}
try {
  const cert = await fetchFingerprint(dpsk.host, dpsk.port ?? 8443);
  console.log(`vSZ ${dpsk.host}:${dpsk.port ?? 8443}`);
  console.log(`  certificate for: ${cert.subject ?? '(no name)'}, valid until ${cert.validTo}`);
  console.log(`  fingerprint:     ${cert.fingerprint256}`);
  console.log('\nPut it in config.json:\n  "tlsFingerprint": "' + cert.fingerprint256 + '"');
  console.log('If the vSZ certificate is ever replaced, update this value or the platform will refuse to connect.');
} catch (err) {
  console.error(`Couldn't connect: ${err.message}`);
  process.exitCode = 1;
}
