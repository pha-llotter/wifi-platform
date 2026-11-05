// Sites visited per person, from the school firewall's logs (a FortiGate's web filter or
// DNS filter, sent by syslog). The firewall knows which site each connection went to but
// not who the device belongs to; the platform knows who had each device address from the
// vSZ's accounting (sessions), so each log line is matched to a person here.
//
// Only the site's name is recorded (www.youtube.com → youtube.com), never pages: with
// HTTPS the firewall only sees the name unless it decrypts traffic, which this doesn't need.
// Visits are grouped per person, device, site and hour, and deleted after
// browsing.retentionDays. Off unless browsing.enabled, and only accepted from
// browsing.allowFrom (the school's public IP), on TCP (RFC 6587 framing) or UDP.
import dgram from 'node:dgram';
import net from 'node:net';
import { ipAllowed } from './admin.js';

/** key=value and key="value" pairs from a FortiGate log line (default or RFC 5424 format). */
export function fields(line) {
  const out = {};
  for (const m of String(line).matchAll(/([A-Za-z_][\w-]*)=(?:"((?:[^"\\]|\\.)*)"|(\S+))/g)) out[m[1]] = m[2] ?? m[3];
  return out;
}

// Two-part endings where the site's own name is the third label from the right.
const TWO_PART = new Set(
  'co.za org.za ac.za gov.za net.za edu.za web.za nom.za school.za co.uk org.uk ac.uk gov.uk me.uk com.au net.au org.au edu.au gov.au co.nz org.nz com.br co.in co.jp com.cn com.ng co.ke com.na co.bw co.zw com.sg com.my co.id com.mx com.ar com.tr'.split(' '),
);

// Companies whose services share one name: keep the service, so Classroom isn't shown as Google search.
const KEEP_SERVICE = new Set(['google.com', 'microsoft.com', 'live.com', 'apple.com', 'sharepoint.com']);

/** The site a host name belongs to: "rr3---sn-x.googlevideo.com" → "googlevideo.com". Null for addresses. */
export function siteOf(host) {
  let h = String(host ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (!h || /^[\d.]+$/.test(h) || h.includes(':') || !/^[a-z0-9.-]+$/.test(h) || !h.includes('.')) return null;
  const parts = h.split('.');
  let take = parts.length >= 3 && TWO_PART.has(parts.slice(-2).join('.')) ? 3 : 2;
  if (KEEP_SERVICE.has(parts.slice(-2).join('.')) && parts.length >= 3 && parts[parts.length - 3] !== 'www') take = 3;
  return parts.slice(-take).join('.');
}

/** A log line's time in ms: eventtime (s, ms, µs or ns since 1970), else date + time + tz. */
function timeOf(f, now) {
  let t = null;
  if (/^\d+$/.test(f.eventtime ?? '')) {
    const n = Number(f.eventtime);
    t = n > 1e17 ? n / 1e6 : n > 1e14 ? n / 1e3 : n > 1e11 ? n : n * 1000;
  } else if (f.date && f.time) {
    const tz = /^[+-]\d{4}$/.test(f.tz ?? '') ? `${f.tz.slice(0, 3)}:${f.tz.slice(3)}` : '';
    t = Date.parse(`${f.date}T${f.time}${tz}`);
  }
  // A firewall clock that's far off would put visits on the wrong day: use the arrival time.
  return Number.isFinite(t) && t <= now + 5 * 60_000 && t >= now - 86_400_000 ? Math.round(t) : now;
}

/** The visit in one log line: { ip, site, category, at }, or null when the line isn't one. */
export function parseLine(line, now = Date.now()) {
  const f = fields(line);
  let host = null;
  if (f.subtype === 'webfilter') host = f.hostname;
  else if (f.subtype === 'dns') host = f.qname;
  else if (f.type === 'traffic') host = f.hostname;
  const site = siteOf(host);
  if (!site || !f.srcip) return null;
  return { ip: f.srcip, site, category: f.catdesc || null, at: timeOf(f, now) };
}

/** Splits a TCP syslog stream into messages: octet counting ("123 <...>") or one per line. */
export function framer(onMessage) {
  let buf = Buffer.alloc(0);
  return (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      const head = /^(\d{1,6}) /.exec(buf.subarray(0, 8).toString('latin1'));
      if (head) {
        const start = head[0].length;
        const len = Number(head[1]);
        if (buf.length < start + len) break;
        onMessage(buf.subarray(start, start + len).toString('utf8'));
        buf = buf.subarray(start + len);
        continue;
      }
      const nl = buf.indexOf(0x0a);
      if (nl < 0) {
        if (buf.length > 64 * 1024) buf = Buffer.alloc(0); // not syslog; don't grow forever
        break;
      }
      const line = buf.subarray(0, nl).toString('utf8').trim();
      buf = buf.subarray(nl + 1);
      if (line) onMessage(line);
    }
  };
}

export function createBrowsing({ config, db, log, flushMs = 5_000 }) {
  const cfg = config.browsing;
  const vlans = new Set(cfg.vlans);
  const status = { enabled: cfg.enabled, lastMessage: null, lastMatched: null, received: 0, matched: 0, unmatched: 0, skipped: 0, refused: 0, lastRefusedFrom: null };
  let pending = new Map();
  const whoCache = new Map(); // "ip|minute" → match, so a busy device isn't looked up per line

  function lookup(ip, at) {
    const key = `${ip}|${Math.floor(at / 60_000)}`;
    if (whoCache.has(key)) return whoCache.get(key);
    const found = db.whoHadIp(ip, at, config.radius.accountingStaleMinutes * 60_000);
    if (whoCache.size > 20_000) whoCache.clear();
    whoCache.set(key, found);
    return found;
  }

  function handle(message, now = Date.now()) {
    status.received++;
    status.lastMessage = now;
    const visit = parseLine(message, now);
    if (!visit) return;
    const owner = lookup(visit.ip, visit.at);
    if (!owner) {
      status.unmatched++;
      return;
    }
    if (vlans.size && !vlans.has(owner.vlan_id ?? config.dpsk.guestVlanId)) {
      status.skipped++;
      return;
    }
    status.matched++;
    status.lastMatched = now;
    const hour = Math.floor(visit.at / 3_600_000) * 3_600_000;
    const who = String(owner.who).toLowerCase();
    const mac = owner.mac ?? 'unknown';
    const key = `${hour}|${who}|${mac}|${visit.site}`;
    const row = pending.get(key);
    if (row) {
      row.hits++;
      row.first = Math.min(row.first, visit.at);
      row.last = Math.max(row.last, visit.at);
      row.category ??= visit.category;
    } else {
      pending.set(key, { hour, who, mac, site: visit.site, category: visit.category, first: visit.at, last: visit.at, hits: 1 });
    }
  }

  function flush() {
    if (!pending.size) return;
    const rows = [...pending.values()];
    pending = new Map();
    try {
      db.addBrowsing(rows);
    } catch (err) {
      log('browsing_error', { error: err.message });
    }
  }

  const allowed = (ip) => {
    const a = String(ip ?? '').replace(/^::ffff:/, '');
    if (ipAllowed(a, cfg.allowFrom)) return true;
    status.refused++;
    status.lastRefusedFrom = a;
    return false;
  };

  let tcp = null;
  let udp = null;
  let timer = null;

  async function start() {
    if (!cfg.enabled) return;
    tcp = net.createServer((socket) => {
      if (!allowed(socket.remoteAddress)) return socket.destroy();
      socket.setTimeout(10 * 60_000, () => socket.destroy());
      socket.on('data', framer((m) => handle(m)));
      socket.on('error', () => {});
    });
    udp = dgram.createSocket('udp4');
    udp.on('message', (msg, rinfo) => {
      if (allowed(rinfo.address)) handle(msg.toString('utf8'));
    });
    udp.on('error', (err) => log('browsing_error', { error: `UDP: ${err.message}` }));
    await new Promise((resolve, reject) => tcp.once('error', reject).listen(cfg.listen.port, cfg.listen.host, resolve));
    await new Promise((resolve, reject) => {
      udp.once('error', reject);
      udp.bind(tcp.address().port, cfg.listen.host, resolve);
    });
    timer = setInterval(flush, flushMs);
    timer.unref();
  }

  return {
    start,
    handle,
    flush,
    status: () => ({ ...status }),
    port: () => tcp?.address()?.port ?? null,
    close() {
      clearInterval(timer);
      flush();
      tcp?.close();
      udp?.close();
    },
  };
}
