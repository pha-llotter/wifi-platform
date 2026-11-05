// Makes the WiFi profile Windows 10/11 laptops need for the school SSID: EAP-TTLS with
// PAP, trusting only the RADIUS server's certificate name under Let's Encrypt's roots.
// Set up by hand, Windows offers "Continue connecting?" for any certificate, so a fake
// access point could collect passwords; with this profile it refuses instead.
//   node scripts/windows-profile.js /etc/wifi-portal/config.json Nexus.xml
// On each laptop (or through Intune / Group Policy):
//   netsh wlan add profile filename="Nexus.xml" user=all
// Then connect to the SSID and enter the school email and password once.
// --root-hash "AA BB …" adds another trusted root's SHA-1 thumbprint, should Let's
// Encrypt change roots.
import fs from 'node:fs';
import { loadConfig } from '../src/config.js';

const args = process.argv.slice(2);
const rootArg = args.indexOf('--root-hash');
const extraRoots = rootArg >= 0 ? [args.splice(rootArg, 2)[1]] : [];
const [configFile = 'config.json', out = 'school-wifi.xml'] = args;
const config = loadConfig(configFile);
const { ssid, serverName } = config.radius;

// SHA-1 thumbprints of ISRG Root X1 (RSA) and ISRG Root X2 (ECDSA), Let's Encrypt's roots.
const roots = ['CABD2A79A1076A31F21D253635CB039D4329A5E8', 'BDB1B93CD5978D45C6261455F8DB95C75AD153AF', ...extraRoots]
  .map((h) => h.replace(/[^0-9a-f]/gi, '').toUpperCase())
  .map((h) => h.match(/../g).join(' '));
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const hex = Buffer.from(ssid, 'utf8').toString('hex').toUpperCase();

const profile = `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>${esc(ssid)}</name>
  <SSIDConfig>
    <SSID>
      <hex>${hex}</hex>
      <name>${esc(ssid)}</name>
    </SSID>
    <nonBroadcast>false</nonBroadcast>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2</authentication>
        <encryption>AES</encryption>
        <useOneX>true</useOneX>
      </authEncryption>
      <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
        <authMode>user</authMode>
        <EAPConfig>
          <EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
            <EapMethod>
              <Type xmlns="http://www.microsoft.com/provisioning/EapCommon">21</Type>
              <VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId>
              <VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType>
              <AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">311</AuthorId>
            </EapMethod>
            <Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig">
              <EapTtls xmlns="http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1">
                <ServerValidation>
                  <ServerNames>${esc(serverName)}</ServerNames>
${roots.map((r) => `                  <TrustedRootCAHash>${r}</TrustedRootCAHash>`).join('\n')}
                  <DisablePrompt>true</DisablePrompt>
                </ServerValidation>
                <Phase2Authentication>
                  <PAPAuthentication/>
                </Phase2Authentication>
                <Phase1Identity>
                  <IdentityPrivacy>true</IdentityPrivacy>
                  <AnonymousIdentity>anonymous</AnonymousIdentity>
                </Phase1Identity>
              </EapTtls>
            </Config>
          </EapHostConfig>
        </EAPConfig>
      </OneX>
    </security>
  </MSM>
</WLANProfile>
`;
fs.writeFileSync(out, profile);
console.log(`Wrote ${out} for ${ssid}, trusting only ${serverName} under Let's Encrypt's roots.`);
console.log(`Install: netsh wlan add profile filename="${out}" user=all`);
