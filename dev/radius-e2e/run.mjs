// End-to-end test of a school SSID login: real EAP-TTLS logins with eapol_test against
// FreeRADIUS (built from deploy/freeradius), an LDAP stand-in for Google, and this
// platform deciding the VLAN. Needs Docker and openssl.   npm run test:radius
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const out = path.join(here, 'out');
const clients = path.join(here, 'clients');
const compose = (...args) => execFileSync('docker', ['compose', '-f', path.join(here, 'docker-compose.yml'), ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const env = { ...process.env, MSYS_NO_PATHCONV: '1' };

function openssl(args) {
  execFileSync('openssl', args, { cwd: out, stdio: 'ignore', env });
}

function makeCertificates() {
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(out, { recursive: true });
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '2', '-subj', '/CN=Test RADIUS CA']);
  openssl(['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key', '-out', 'server.csr', '-subj', '/CN=radius.test']);
  fs.writeFileSync(path.join(out, 'server.ext'), 'subjectAltName=DNS:radius.test\nextendedKeyUsage=serverAuth\n');
  openssl(['x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'server.pem', '-days', '2', '-extfile', 'server.ext']);
  openssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'client.key', '-out', 'client.pem', '-days', '2', '-subj', '/CN=dummy-ldap-client']);
  for (const f of fs.readdirSync(out)) fs.chmodSync(path.join(out, f), 0o644);
}

function writeClients() {
  fs.rmSync(clients, { recursive: true, force: true });
  fs.mkdirSync(clients, { recursive: true });
  const conf = (identity, password) => `network={
  key_mgmt=WPA-EAP
  eap=TTLS
  identity="${identity}"
  anonymous_identity="anonymous@phahs.org.za"
  password="${password}"
  phase2="auth=PAP"
  ca_cert="/certs/ca.pem"
  domain_suffix_match="radius.test"
}
`;
  const cases = {
    staff: ['t.smith', 'Staff-Pass-1'],
    pupil: ['pupil@phahs.org.za', 'Pupil-Pass-1'],
    wrongpw: ['t.smith@phahs.org.za', 'not-the-password'],
    exam: ['exam.room1', 'Exam-Pass-1'],
    blocked: ['blocked.user', 'Blocked-Pass-1'],
    stranger: ['nobody@phahs.org.za', 'whatever'],
  };
  for (const [name, [id, pw]] of Object.entries(cases)) fs.writeFileSync(path.join(clients, `${name}.conf`), conf(id, pw));
}

async function startPlatform(token = 'e2e-token-0123456789abcdef') {
  const fakeVsz = spawn(process.execPath, [path.join(root, 'dev/fake-vsz.js')], { stdio: 'ignore' });
  const dbFile = path.join(out, 'platform.db');
  const { openDb } = await import(new URL('../../src/db.js', import.meta.url));
  const db = openDb(dbFile);
  db.block('blocked.user@phahs.org.za', 'e2e test', 'test');
  db.rememberDevice({ mac: '02:00:00:00:00:42', email: 'pupil@phahs.org.za', ssid: 'Nexus' }, 90);
  db.close();
  const config = {
    publicUrl: 'http://localhost:18099',
    http: { host: '0.0.0.0', port: 18099 },
    google: { clientId: 'cid', clientSecret: 'cs', allowedDomains: ['phahs.org.za'], ldap: { clientCert: path.join(out, 'client.pem'), clientKey: path.join(out, 'client.key') } },
    portal: { networks: { Nexus: 30, 'Nexus Staff': 20 }, nbi: { host: '127.0.0.1', port: 18444, protocol: 'http', password: 'nbi' } },
    radius: { apiToken: token, apiAllowFrom: ['0.0.0.0/0'] },
    dpsk: { host: '127.0.0.1', port: 18443, protocol: 'http', username: 'dev', password: 'dev', zoneId: 'zone-1', wlanId: 'wlan-1', ssid: 'Guest' },
    policy: {
      rules: [
        { name: 'Exam rooms', email: '^exam\\.', deny: true, message: 'Exam accounts stay offline.' },
        { name: 'Staff', email: '^t\\.', vlanId: 20 },
        { name: 'Learners', vlanId: 30 },
      ],
      default: null,
    },
    admin: { emails: ['it@phahs.org.za'] },
    database: dbFile,
    logFile: path.join(out, 'platform.jsonl'),
  };
  fs.writeFileSync(path.join(out, 'platform.json'), JSON.stringify(config));
  const platform = spawn(process.execPath, [path.join(root, 'src/server.js'), path.join(out, 'platform.json')], { stdio: ['ignore', 'ignore', 'inherit'] });
  for (let i = 0; i < 50; i++) {
    try {
      if ((await fetch('http://127.0.0.1:18099/healthz')).ok) return { platform, fakeVsz };
    } catch {}
    await sleep(200);
  }
  throw new Error('platform did not start');
}

function login(name) {
  try {
    const output = compose('run', '--rm', 'eapol', '-c', `/conf/${name}.conf`, '-a', '172.31.250.10', '-p', '1812', '-s', 'testing123', '-t', '15', '-M', '02:00:00:00:00:01');
    return { ok: /SUCCESS/.test(output), output };
  } catch (err) {
    return { ok: false, output: `${err.stdout ?? ''}${err.stderr ?? ''}` };
  }
}

// eapol_test prints the RADIUS reply with values in hex; Tunnel-Private-Group-Id
// (attribute 81) holds the VLAN as text, e.g. 3230 = "20".
function vlanOf(output) {
  const m = output.match(/Attribute 81 \(Tunnel-Private-Group-Id\) length=\d+\s+Value: ([0-9a-f]+)/i);
  if (!m) return null;
  const text = Buffer.from(m[1], 'hex').toString('latin1').replace(/^\0/, ''); // a leading tag byte, if any
  return Number(text);
}

const results = [];
function expect(name, cond, detail = '') {
  results.push({ name, ok: Boolean(cond) });
  console.log(`${cond ? '✔' : '✖'} ${name}${cond ? '' : `  ${detail}`}`);
}

let procs;
try {
  makeCertificates();
  writeClients();
  console.log('building and starting FreeRADIUS and LDAP…');
  compose('build', '-q');
  compose('up', '-d', 'openldap', 'freeradius');
  procs = await startPlatform();
  await sleep(6000);

  const staff = login('staff');
  expect('staff log in with a bare username and land on VLAN 20', staff.ok && vlanOf(staff.output) === 20, `ok=${staff.ok} vlan=${vlanOf(staff.output)}`);
  const pupil = login('pupil');
  expect('learners land on VLAN 30', pupil.ok && vlanOf(pupil.output) === 30, `ok=${pupil.ok} vlan=${vlanOf(pupil.output)}`);
  expect('a wrong password is refused', !login('wrongpw').ok);
  expect('a rule can refuse an account even with the right password', !login('exam').ok);
  expect('a blocked person is refused even with the right password', !login('blocked').ok);
  expect('an unknown account is refused', !login('stranger').ok);

  const events = fs.readFileSync(path.join(out, 'platform.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  const signedIn = events.filter((e) => e.event === 'signed_in').map((e) => e.email);
  const denied = events.filter((e) => e.event === 'denied').map((e) => `${e.email}: ${e.reason}`);
  expect('the dashboard records the successful logins', signedIn.includes('t.smith@phahs.org.za') && signedIn.includes('pupil@phahs.org.za'), signedIn.join(', '));
  expect('the dashboard records why logins were refused', denied.some((d) => d.startsWith('t.smith@phahs.org.za: wrong password')) && denied.some((d) => d.includes('blocked by an admin')) && denied.some((d) => d.includes('rule "Exam rooms"')), denied.join(' | '));
  expect('the password never reaches the platform', !fs.readFileSync(path.join(out, 'platform.jsonl'), 'utf8').includes('Staff-Pass-1'));

  // The Access-Accept tells the vSZ the real login name (attribute 1, in hex), which it
  // then uses in its accounting.
  const accept = staff.output.slice(staff.output.indexOf('code=2 (Access-Accept)'));
  const userNameHex = Buffer.from('t.smith@phahs.org.za').toString('hex');
  expect(
    'the Access-Accept carries the real login name for accounting',
    accept.length > 22 && new RegExp(`Attribute 1 \\(User-Name\\) length=\\d+\\s+Value: ('t\\.smith@phahs\\.org\\.za'|${userNameHex})`, 'i').test(accept),
    accept.split('\n').slice(0, 14).join(' | '),
  );

  // What the vSZ sends to port 1813: a start, an update with the data used, a stop.
  const account = (attrs) =>
    compose('exec', '-T', 'freeradius', 'sh', '-c', `printf '${attrs.join('\\n')}\\n' | radclient -q 127.0.0.1:1813 acct testing123`);
  const session = ['User-Name = "t.smith@phahs.org.za"', 'Calling-Station-Id = "02-00-00-00-00-01"', 'NAS-Identifier = "vsz"', 'Acct-Session-Id = "e2e-1"', 'Framed-IP-Address = 10.20.1.5'];
  account([...session, 'Acct-Status-Type = Start']);
  account([...session, 'Acct-Status-Type = Interim-Update', 'Acct-Output-Octets = 700000000', 'Acct-Input-Octets = 30000000', 'Acct-Session-Time = 600']);
  account([...session, 'Acct-Status-Type = Stop', 'Acct-Output-Octets = 900000000', 'Acct-Input-Octets = 40000000', 'Acct-Output-Gigawords = 1', 'Acct-Session-Time = 900']);
  await sleep(500);
  const { openDb, dayOf } = await import(new URL('../../src/db.js', import.meta.url));
  const db = openDb(path.join(out, 'platform.db'));
  const used = db.usageOn('t.smith@phahs.org.za', dayOf(Date.now()));
  db.close();
  expect('accounting through FreeRADIUS records the data used (with gigawords)', used.down === 2 ** 32 + 900_000_000 && used.up === 40_000_000, JSON.stringify(used));

  // The sign-in networks (Hotspot / WISPr): PAP requests go to the platform's /radius/portal.
  // A remembered device reconnects by MAC; the sign-in page path uses the same route
  // with a one-time ticket (covered in test/portal.test.js).
  const hotspot = (attrs) => {
    try {
      return compose('exec', '-T', 'freeradius', 'sh', '-c', `printf '${attrs.join('\\n')}\\n' | radclient -x -r 1 -t 5 127.0.0.1:1812 auth testing123`);
    } catch (err) {
      return `${err.stdout ?? ''}${err.stderr ?? ''}`;
    }
  };
  const tail = (text, n) => text.trim().split('\n').slice(-n).join(' | ');
  const macLogin = (mac, ssid) =>
    hotspot([
      `User-Name = "${mac.replace(/:/g, '')}"`,
      `User-Password = "${mac.replace(/:/g, '')}"`,
      `Calling-Station-Id = "${mac.replace(/:/g, '-').toUpperCase()}"`,
      `Called-Station-Id = "AA-BB-CC-00-11-22:${ssid}"`,
    ]);
  const back = macLogin('02:00:00:00:00:42', 'Nexus');
  expect(
    'a remembered device reconnects on its network, with its owner and session length',
    /Access-Accept/.test(back) && /User-Name = "pupil@phahs\.org\.za"/.test(back) && /Session-Timeout = /.test(back),
    tail(back, 8),
  );
  const wrongNet = macLogin('02:00:00:00:00:42', 'Nexus Staff');
  expect("a learner's remembered device is refused on the staff network", /Access-Reject/.test(wrongNet) && /Nexus/.test(wrongNet), tail(wrongNet, 6));
  expect('an unknown device is refused (so the vSZ shows the sign-in page)', /Access-Reject/.test(macLogin('02:00:00:00:00:77', 'Nexus')));
  const guess = hotspot(['User-Name = "pupil@phahs.org.za"', 'User-Password = "Pupil-Pass-1"', 'Calling-Station-Id = "02-00-00-00-00-43"', 'Called-Station-Id = "AA-BB-CC-00-11-22:Nexus"']);
  expect('a school password sent straight to RADIUS is refused: only the sign-in page lets people on', /Access-Reject/.test(guess), tail(guess, 6));

  // The Docker health check in docker-compose.yml (Status-Server to sites/status).
  let health = '';
  try {
    compose('exec', '-T', 'freeradius', 'sh', '-c', `echo 'Message-Authenticator = 0x00' | radclient -q -r 1 -t 3 127.0.0.1:18121 status "$RADIUS_SECRET"`);
    health = 'ok';
  } catch (err) {
    health = `${err.stdout ?? ''}${err.stderr ?? ''}`;
  }
  expect('the FreeRADIUS health check answers', health === 'ok', health);

  // If FreeRADIUS and the platform disagree on the token, the platform answers 404:
  // logins must then be refused, never let through without the platform's decision.
  procs.platform.kill();
  procs.fakeVsz.kill();
  await sleep(500);
  procs = await startPlatform('a-different-token-0123456789');
  const mismatch = login('staff');
  expect('a token mismatch refuses logins instead of skipping the rules', !mismatch.ok, mismatch.output.split('\n').filter((l) => /SUCCESS|FAILURE|Access-/.test(l)).join(' | '));
} catch (err) {
  console.error(err.stdout ?? '', err.stderr ?? '', err.message);
  results.push({ name: 'run', ok: false });
} finally {
  procs?.platform.kill();
  procs?.fakeVsz.kill();
  if (!process.env.KEEP) {
    try {
      compose('down', '-v');
    } catch {}
  }
}
const failed = results.filter((r) => !r.ok).length;
console.log(failed ? `\n${failed} failed` : `\nall ${results.length} passed`);
process.exitCode = failed ? 1 : 0;
