// Lists the vSZ zones and WLANs with their ids, to fill in dpsk.zoneId and dpsk.wlanId.
//   node scripts/vsz-wlans.js /etc/wifi-portal/config.json
// Only dpsk.host, port, username and password need to be set for this to run.
import { createVszClient } from '../src/vsz.js';
import fs from 'node:fs';

const file = process.argv[2] ?? process.env.WIFI_PORTAL_CONFIG ?? 'config.json';
const { dpsk = {} } = JSON.parse(fs.readFileSync(file, 'utf8'));
if (!dpsk.host || !dpsk.username || !dpsk.password) {
  console.error(`Set dpsk.host, dpsk.username and dpsk.password in ${file} first.`);
  process.exit(1);
}

const vsz = createVszClient({ port: 8443, apiVersion: 'v9_1', ...dpsk, zoneId: '-', wlanId: '-' });
try {
  for (const zone of await vsz.listZones()) {
    console.log(`\nZone "${zone.name}"\n  zoneId: ${zone.id}`);
    for (const wlan of await vsz.listWlans(zone.id)) {
      console.log(`  WLAN "${wlan.name}" (SSID ${wlan.ssid ?? wlan.name})\n    wlanId: ${wlan.id}`);
    }
  }
  console.log('\nThe WLAN must use DPSK (in the vSZ: WLAN → Authentication Options → Dynamic PSK).');
} catch (err) {
  console.error(err.message);
  process.exitCode = 1;
} finally {
  await vsz.close();
}
