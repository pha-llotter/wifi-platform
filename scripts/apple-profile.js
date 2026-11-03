// Makes the setup profile (.mobileconfig) iPhones, iPads and Macs need for the school
// SSID. Joined by hand, Apple devices send the password with MSCHAPv2, which Google
// can't check; this profile tells them to use EAP-TTLS with PAP and to trust only the
// RADIUS server's certificate name. It asks for the username and password on install.
//   node scripts/apple-profile.js /etc/wifi-portal/config.json PHA-WiFi.mobileconfig
// Share the file by email or AirDrop; opening it offers to install the profile.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { loadConfig } from '../src/config.js';

const [configFile = 'config.json', out = 'school-wifi.mobileconfig'] = process.argv.slice(2);
const config = loadConfig(configFile);
const { ssid, serverName } = config.radius;
const org = config.branding.school || config.branding.name;
const domain = config.radius.defaultDomain;
const id = domain.split('.').reverse().join('.');

// Stable UUIDs, so installing a newer profile replaces the old one.
const uuid = (name) => {
  const hex = crypto.createHash('sha256').update(`${id}:${ssid}:${name}`).digest('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`.toUpperCase();
};
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const profile = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>AutoJoin</key>
      <true/>
      <key>EAPClientConfiguration</key>
      <dict>
        <key>AcceptEAPTypes</key>
        <array>
          <integer>21</integer>
        </array>
        <key>TTLSInnerAuthentication</key>
        <string>PAP</string>
        <key>TLSTrustedServerNames</key>
        <array>
          <string>${esc(serverName)}</string>
        </array>
      </dict>
      <key>EncryptionType</key>
      <string>WPA</string>
      <key>HIDDEN_NETWORK</key>
      <false/>
      <key>PayloadDisplayName</key>
      <string>${esc(ssid)}</string>
      <key>PayloadIdentifier</key>
      <string>${esc(id)}.wifi.${esc(ssid)}</string>
      <key>PayloadType</key>
      <string>com.apple.wifi.managed</string>
      <key>PayloadUUID</key>
      <string>${uuid('network')}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>SSID_STR</key>
      <string>${esc(ssid)}</string>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>Connects this device to ${esc(ssid)} with your school Google account.</string>
  <key>PayloadDisplayName</key>
  <string>${esc(ssid)} (${esc(org)})</string>
  <key>PayloadIdentifier</key>
  <string>${esc(id)}.wifi</string>
  <key>PayloadOrganization</key>
  <string>${esc(org)}</string>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>${uuid('profile')}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
`;
fs.writeFileSync(out, profile);
console.log(`Wrote ${out} for ${ssid}, trusting the certificate for ${serverName}.`);
