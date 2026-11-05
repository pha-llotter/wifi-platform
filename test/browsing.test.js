// Sites visited per person, from the school firewall's syslog (src/browsing.js).
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import net from 'node:net';
import { after, before, beforeEach, describe, test } from 'node:test';
import { createBrowsing, fields, framer, parseLine, siteOf } from '../src/browsing.js';
import { normalizeConfig } from '../src/config.js';
import { startPlatform } from './helpers.js';

const NOW = Date.parse('2026-11-05T10:42:00+02:00');
const NS = `${NOW}000000`;

// What a FortiGate sends: a web filter line (default format) and a DNS filter line (RFC 5424).
const webLine = (ip, host, extra = '') =>
  `<189>date=2026-11-05 time=10:42:00 devname="FG200G" devid="FG200G0000" logid="0316013057" type="utm" subtype="webfilter" eventtype="ftgd_allow" level="notice" vd="root" eventtime=${NS} tz="+0200" policyid=7 sessionid=123 srcip=${ip} srcport=51234 srcintf="vlan10" dstip=142.250.74.110 dstport=443 hostname="${host}" profile="wifi-log" action="passthrough" reqtype="direct" url="https://${host}/" sentbyte=512 rcvdbyte=0 direction="outgoing" msg="URL belongs to an allowed category in policy" method="domain" cat=25 catdesc="Streaming Media and Download"${extra}`;
const dnsLine = (ip, qname) =>
  `<189>1 2026-11-05T10:43:00+02:00 FG200G - - - date=2026-11-05 time=10:43:00 logid="1501054802" type="utm" subtype="dns" eventtype="dns-response" srcip=${ip} srcport=53000 dstip=8.8.8.8 qname="${qname}" qtype="A" action="pass" catdesc="Education"`;

describe('reading FortiGate log lines', () => {
  test('pairs with and without quotes', () => {
    assert.deepEqual(fields('a=1 b="two words" c="x\\"y"'), { a: '1', b: 'two words', c: 'x\\"y' });
  });

  test('a host name becomes the site it belongs to', () => {
    assert.equal(siteOf('www.youtube.com'), 'youtube.com');
    assert.equal(siteOf('rr3---sn-xx.googlevideo.com.'), 'googlevideo.com');
    assert.equal(siteOf('www.phahs.org.za'), 'phahs.org.za');
    assert.equal(siteOf('news.bbc.co.uk'), 'bbc.co.uk');
    assert.equal(siteOf('classroom.google.com'), 'classroom.google.com', 'Google services stay apart');
    assert.equal(siteOf('www.google.com'), 'google.com');
    assert.equal(siteOf('142.250.74.110'), null);
    assert.equal(siteOf('localhost'), null);
  });

  test('a web filter line gives the device address, site, category and time', () => {
    assert.deepEqual(parseLine(webLine('10.10.0.5', 'www.youtube.com'), NOW + 1000), {
      ip: '10.10.0.5',
      site: 'youtube.com',
      category: 'Streaming Media and Download',
      at: NOW,
    });
  });

  test('a DNS filter line in RFC 5424 format works too, timed from date, time and tz', () => {
    const v = parseLine(`${dnsLine('10.10.0.5', 'en.wikipedia.org')} tz="+0200"`, NOW + 120_000);
    assert.equal(v.site, 'wikipedia.org');
    assert.equal(v.at, NOW + 60_000);
  });

  test('other log lines are ignored', () => {
    assert.equal(parseLine('<190>date=2026-11-05 type="event" subtype="system" msg="Admin login"'), null);
  });

  test('TCP framing: octet counting and one message per line, split anywhere', () => {
    const got = [];
    const feed = framer((m) => got.push(m));
    const a = 'first message';
    const b = '<189>second';
    const stream = Buffer.from(`${Buffer.byteLength(a)} ${a}${Buffer.byteLength(b)} ${b}third line\nfourth\n`);
    for (let i = 0; i < stream.length; i += 5) feed(stream.subarray(i, i + 5));
    assert.deepEqual(got, [a, b, 'third line', 'fourth']);
  });
});

describe('matching visits to people', () => {
  let h;
  const config = (browsing) => ({ browsing: { enabled: true, allowFrom: ['127.0.0.1'], listen: { host: '127.0.0.1', port: 0 }, ...browsing } });

  const signedIn = (who, mac, ip, vlanId) => {
    h.db.recordLogin({ email: who, mac, vlanId }, NOW - 3600_000);
    h.db.recordAccounting({ status: 'Start', sessionId: `s-${mac}`, who, mac, ip, nas: 'vsz', down: 0, up: 0 }, NOW - 3600_000);
    h.db.recordAccounting({ status: 'Interim-Update', sessionId: `s-${mac}`, who, mac, ip, nas: 'vsz', down: 10, up: 10 }, NOW - 300_000);
  };

  beforeEach(async () => {
    h?.close();
    h = await startPlatform(config({}));
    signedIn('pupil@school.org', '02:00:00:00:00:01', '10.10.0.5', 30);
    signedIn('t.smith@school.org', '02:00:00:00:00:02', '10.20.0.9', 20);
  });
  after(() => h?.close());

  test('visits are grouped per person, device, site and hour', () => {
    const b = createBrowsing({ config: h.config, db: h.db, log: () => {} });
    b.handle(webLine('10.10.0.5', 'www.youtube.com'), NOW);
    b.handle(webLine('10.10.0.5', 'i.ytimg.com'), NOW);
    b.handle(webLine('10.10.0.5', 'm.youtube.com'), NOW);
    b.handle(webLine('10.99.0.1', 'www.youtube.com'), NOW); // no one had this address
    b.flush();
    const sites = h.db.personSites('pupil@school.org', NOW - 3600_000, NOW + 3600_000);
    assert.deepEqual(sites.map((s) => [s.site, s.hits]), [['youtube.com', 2], ['ytimg.com', 1]]);
    assert.equal(sites[0].category, 'Streaming Media and Download');
    assert.equal(b.status().matched, 3);
    assert.equal(b.status().unmatched, 1);
  });

  test('only the VLANs in browsing.vlans are recorded', async () => {
    h.close();
    h = await startPlatform(config({ vlans: [30] }));
    signedIn('pupil@school.org', '02:00:00:00:00:01', '10.10.0.5', 30);
    signedIn('t.smith@school.org', '02:00:00:00:00:02', '10.20.0.9', 20);
    const b = createBrowsing({ config: h.config, db: h.db, log: () => {} });
    b.handle(webLine('10.10.0.5', 'www.youtube.com'), NOW);
    b.handle(webLine('10.20.0.9', 'www.youtube.com'), NOW);
    b.flush();
    assert.equal(h.db.personSites('pupil@school.org', 0, NOW * 2).length, 1);
    assert.equal(h.db.personSites('t.smith@school.org', 0, NOW * 2).length, 0, 'staff on VLAN 20 are not recorded');
    assert.equal(b.status().skipped, 1);
  });

  test('a device that has moved on is matched to whoever had the address at the time', () => {
    h.db.recordAccounting({ status: 'Stop', sessionId: 's-02:00:00:00:00:01', who: 'pupil@school.org', mac: '02:00:00:00:00:01', ip: '10.10.0.5', nas: 'vsz', down: 20, up: 20 }, NOW - 60_000 * 10);
    h.db.recordAccounting({ status: 'Start', sessionId: 's-3', who: 'other@school.org', mac: '02:00:00:00:00:03', ip: '10.10.0.5', nas: 'vsz', down: 0, up: 0 }, NOW - 60_000 * 5);
    assert.equal(h.db.whoHadIp('10.10.0.5', NOW - 60_000 * 30).who, 'pupil@school.org');
    assert.equal(h.db.whoHadIp('10.10.0.5', NOW).who, 'other@school.org');
  });

  test('received over TCP and UDP, and only from browsing.allowFrom', async () => {
    const b = createBrowsing({ config: h.config, db: h.db, log: () => {}, flushMs: 50 });
    await b.start();
    const port = b.port();
    const line = webLine('10.10.0.5', 'www.wikipedia.org').replace(`eventtime=${NS}`, `eventtime=${Date.now()}000000`);
    await new Promise((resolve) => {
      const sock = net.connect(port, '127.0.0.1', () => sock.end(`${Buffer.byteLength(line)} ${line}`, resolve));
    });
    const udp = dgram.createSocket('udp4');
    await new Promise((resolve) => udp.send(dnsLine('10.10.0.5', 'www.khanacademy.org'), port, '127.0.0.1', resolve));
    udp.close();
    for (let i = 0; i < 40 && b.status().received < 2; i++) await new Promise((r) => setTimeout(r, 25));
    b.close();
    assert.equal(b.status().received, 2);
    assert.equal(b.status().refused, 0);
  });

  test('logs from any other address are refused', async () => {
    h.config.browsing.allowFrom = ['192.0.2.1'];
    const b = createBrowsing({ config: h.config, db: h.db, log: () => {} });
    await b.start();
    await new Promise((resolve) => {
      const sock = net.connect(b.port(), '127.0.0.1', () => sock.write(`${webLine('10.10.0.5', 'evil.example')}\n`));
      sock.on('close', resolve);
      sock.on('error', resolve);
    });
    b.close();
    assert.equal(b.status().received, 0);
    assert.equal(b.status().refused, 1);
    assert.equal(b.status().lastRefusedFrom, '127.0.0.1');
  });
});

describe('sites in the dashboard', () => {
  let h;
  before(async () => {
    h = await startPlatform({
      admin: { emails: ['it@school.org', 'head@school.org'] },
      browsing: { enabled: true, allowFrom: ['127.0.0.1'], viewers: ['head@school.org'] },
    });
    h.db.addBrowsing([{ hour: Math.floor(Date.now() / 3600_000) * 3600_000, who: 'pupil@school.org', mac: '02:00:00:00:00:01', site: 'youtube.com', category: 'Streaming', first: Date.now(), last: Date.now(), hits: 4 }]);
  });
  after(() => h.close());

  test('only the admins in browsing.viewers can see sites, and every look is in the audit log', async () => {
    const it = await h.loginAdmin('it@school.org');
    const head = await h.loginAdmin('head@school.org');
    assert.equal((await h.req('/admin/api/me', { cookie: it.cookie })).json.browsing.canView, false);
    assert.equal((await h.req('/admin/api/people/pupil%40school.org/sites', { cookie: it.cookie })).res.status, 403);
    assert.equal((await h.req('/admin/api/sites', { cookie: it.cookie })).res.status, 403);

    const r = await h.req('/admin/api/people/pupil%40school.org/sites', { cookie: head.cookie });
    assert.equal(r.res.status, 200);
    assert.deepEqual(r.json.sites.map((s) => [s.site, s.hits]), [['youtube.com', 4]]);
    const audit = h.db.events({ category: 'admin' }).find((e) => e.detail.action === 'viewed sites visited');
    assert.equal(audit.detail.by, 'head@school.org');
    assert.equal(audit.email, 'pupil@school.org');

    const top = await h.req('/admin/api/sites?period=today', { cookie: head.cookie });
    assert.deepEqual(top.json.top.map((s) => [s.site, s.people]), [['youtube.com', 1]]);
  });

  test("the connection guide says websites are recorded when they are", async () => {
    const it = await h.loginAdmin('it@school.org');
    const guide = await h.req('/admin/guide', { cookie: it.cookie });
    assert.match(guide.text, /also records <strong>which websites you visit<\/strong>/);
    assert.doesNotMatch(guide.text, /does <strong>not<\/strong> record which websites/);
  });

  test('config: browsing needs allowFrom when it is on', () => {
    assert.throws(() => normalizeConfig({ ...h.config, browsing: { enabled: true } }), /browsing.allowFrom/);
  });
});
