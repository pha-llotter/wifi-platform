// WiFi admin dashboard. Plain JS, no build step: hash routes render into #view from
// the JSON API under /admin/api. Every value from the server goes through h().
//   School SSID: people log in with their Google account (802.1X); this shows who,
//                from which devices, on which VLAN, and who was turned away.
//   Guest SSID:  visitor keys (DPSK) with end dates, made and printed here.

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const view = $('#view');
let me = null;
let refreshTimer = null;

const h = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET') headers['X-CSRF-Token'] = me?.csrf ?? '';
  const res = await fetch(`/admin/api${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  if (res.status === 401) {
    location.href = '/admin';
    throw new Error('Signed out');
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const problems = data.problems ?? ['Something went wrong. Try again.'];
    throw Object.assign(new Error(problems.join(' ')), { problems });
  }
  return data;
}

function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove('show'), 2400);
}

/* ---------- formatting ---------- */

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
function ago(ms) {
  const s = Math.round((ms - Date.now()) / 1000);
  const a = Math.abs(s);
  if (a < 45) return s <= 0 ? 'just now' : 'in a moment';
  if (a < 3600) return rtf.format(Math.round(s / 60), 'minute');
  if (a < 86400) return rtf.format(Math.round(s / 3600), 'hour');
  return rtf.format(Math.round(s / 86400), 'day');
}
const fullDate = (ms) => new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const when = (ms) => (ms ? `<time class="nowrap" datetime="${new Date(ms).toISOString()}" title="${h(fullDate(ms))}">${h(ago(ms))}</time>` : '<span class="faint">—</span>');
const num = (n) => new Intl.NumberFormat().format(n ?? 0);
const dash = (v) => (v ? h(v) : '<span class="faint">—</span>');
const vlan = (v) => (v ? num(v) : '<span class="faint">Default</span>');
function bytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = Number(n) || 0;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}
function duration(ms) {
  const m = Math.round(ms / 60_000);
  return m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${m % 60} min`;
}
// A bar scaled to the largest value in the table, with the figure always written out.
const usageCell = (value, max) =>
  `<div class="usage-cell"><div class="usage-bar" aria-hidden="true"><span data-w="${max ? Math.max(1, Math.round((value / max) * 100)) : 0}"></span></div><span class="val">${h(bytes(value))}</span></div>`;
const who = (w) => (w.includes('@') && !w.startsWith('guest: ') ? personLink(w) : h(w));
// Bar widths are set from script: the dashboard's CSP doesn't allow inline style attributes.
const sizeBars = (root) => {
  for (const el of $$('[data-w]', root)) el.style.width = `${el.dataset.w}%`;
};

const ICON = {
  ok: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
  warn: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 8.5v4.5"/><path d="M12 16.5v.01"/><path d="M10.3 3.9 2.4 17.6a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>',
  bad: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/></svg>',
  info: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8v.01"/></svg>',
  up: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 15l6-6 6 6"/></svg>',
  down: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>',
  trash: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16"/><path d="M10 11v6M14 11v6"/><path d="M6 7l1 13h10l1-13"/><path d="M9 7V4h6v3"/></svg>',
  back: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M15 6l-6 6 6 6"/></svg>',
};
const badge = (tone, text) => `<span class="badge badge-${tone}">${ICON[tone] ?? ''}${h(text)}</span>`;
const checkIcon = (tone) => ICON[tone].replace('<svg ', `<svg class="icon ${tone}" `);

/* ---------- activity labels ---------- */

const CATEGORY = {
  signin: ['ok', 'Logged in'],
  denied: ['warn', 'Turned away'],
  keys: ['info', 'Guest SSID'],
  usage: ['warn', 'High usage'],
  error: ['bad', 'Problem'],
  admin: ['info', 'Admin'],
  system: ['', 'Platform'],
};
const TYPE_LABEL = {
  signed_in: 'Logged in',
  usage_high: 'High usage',
  denied: 'Turned away',
  key_issued: 'Key made',
  key_revoked: 'Key removed',
  key_reset: 'Key reset',
  key_missing: 'Key gone',
  keys_adopted: 'Keys adopted',
  key_sync: 'Keys synced',
  key_sync_error: 'Sync problem',
  vsz_error: 'vSZ problem',
  directory_error: 'Google directory problem',
  google_error: 'Google sign-in problem',
  backup: 'Backup made',
  backup_error: 'Backup failed',
  alert_sent: 'Alert emailed',
  alert_error: 'Alert failed',
  admin_denied: 'Admin sign-in refused',
  started: 'Platform started',
  stopping: 'Platform stopped',
};

function eventBadge(e) {
  const [tone, label] = CATEGORY[e.category] ?? ['', e.type];
  const text = e.type === 'admin' ? 'Admin' : (TYPE_LABEL[e.type] ?? label);
  return tone ? badge(tone, text) : `<span class="badge">${h(text)}</span>`;
}

function eventDetail(e) {
  const d = e.detail ?? {};
  const v = (x) => (x ? `VLAN ${x}` : 'default VLAN');
  switch (e.type) {
    case 'signed_in':
      return [d.rule && `Rule “${d.rule}”`, v(d.vlanId), d.orgUnit].filter(Boolean).join(' · ');
    case 'denied':
      return d.reason ?? 'Not allowed';
    case 'usage_high':
      return `${d.gb} GB today, over the ${d.limitGb} GB alert level`;
    case 'key_issued':
      return `Guest key for “${d.label}”${d.shared ? ' (several devices)' : ''} · ${v(d.vlanId)} · until ${fullDate(d.expires)} · by ${d.by}`;
    case 'key_revoked':
    case 'key_missing':
      return [d.label && `“${d.label}”`, d.reason, d.by && `by ${d.by}`].filter(Boolean).join(' · ');
    case 'key_reset':
      return [`“${d.label}” freed for a new device`, d.mac && `was ${d.mac}`, d.by && `by ${d.by}`].filter(Boolean).join(' · ');
    case 'keys_adopted':
      return `${d.adopted} adopted from the vSZ, ${d.skipped} left alone · by ${d.by}`;
    case 'key_sync':
      return `${d.checked} keys checked · ${d.expired} guest keys ended · ${d.missing} found deleted on the vSZ · ${d.by}`;
    case 'backup':
      return String(d.file ?? '').split(/[\\/]/).pop();
    case 'admin':
      return [d.action, d.by && `by ${d.by}`, d.reason && `“${d.reason}”`].filter(Boolean).join(' ');
    case 'admin_denied':
      return [d.attempted, d.reason, d.ip && `from ${d.ip}`].filter(Boolean).join(' · ');
    default:
      return [d.error ?? d.message ?? d.reason, d.email].filter(Boolean).join(' · ');
  }
}

const personLink = (email) => (email ? `<a href="#people/${encodeURIComponent(email)}">${h(email)}</a>` : '<span class="faint">—</span>');

/* ---------- router ---------- */

const routes = { overview, activity, people, usage, guests, rules, settings };

async function route() {
  clearTimeout(refreshTimer);
  const [name, ...rest] = (location.hash.slice(1) || 'overview').split('/');
  const render = name === 'people' && rest.length ? () => person(decodeURIComponent(rest.join('/'))) : routes[name] ?? overview;
  const section = routes[name] ? name : 'overview';
  for (const a of $$('.mainnav a')) {
    if (a.dataset.view === section) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  if (!view.dataset.view || view.dataset.view !== location.hash) view.innerHTML = '<div class="skeleton"></div>';
  view.dataset.view = location.hash;
  try {
    await render();
  } catch (err) {
    if (err.message !== 'Signed out') view.innerHTML = `<div class="notice notice-bad">${h(err.message)}</div>`;
  }
}

/* ---------- shared pieces ---------- */

function kpi(label, value, note) {
  return kpiText(label, num(value), note);
}

function kpiText(label, text, note) {
  return `<section class="panel kpi"><div class="kpi-label">${h(label)}</div><div class="kpi-value">${h(text)}</div><div class="kpi-note">${note}</div></section>`;
}

function devicesTable(rows, { withPerson = true, empty = 'No logins yet.' } = {}) {
  if (!rows.length) return `<p class="empty">${h(empty)}</p>`;
  return `<div class="table-wrap"><table class="data compact"><thead><tr>
    ${withPerson ? '<th>Person</th>' : ''}<th>Device</th><th>VLAN</th><th>Rule</th><th>Last login</th><th>First seen</th><th class="num">Logins</th>
  </tr></thead><tbody>${rows
    .map(
      (l) => `<tr>
      ${withPerson ? `<td>${personLink(l.email)}</td>` : ''}
      <td class="mono">${h(l.mac)}</td>
      <td>${vlan(l.vlan_id)}</td>
      <td>${dash(l.rule)}</td>
      <td>${when(l.last)}</td>
      <td>${when(l.first)}</td>
      <td class="num">${num(l.count)}</td>
    </tr>`,
    )
    .join('')}</tbody></table></div>`;
}

function keysTable(rows, { empty }) {
  if (!rows.length) return `<p class="empty">${h(empty)}</p>`;
  return `<div class="table-wrap"><table class="data compact"><thead><tr>
    <th>Guest</th><th>VLAN</th><th>Connected device</th><th>Ends</th><th>Made by</th><th>Made</th><th></th>
  </tr></thead><tbody>${rows
    .map(
      (k) => `<tr>
      <td>${h(k.label)}</td>
      <td>${vlan(k.vlan_id)}</td>
      <td class="mono">${k.shared ? '<span class="badge">Several devices</span>' : k.mac ? h(k.mac) : '<span class="faint">Not used yet</span>'}</td>
      <td>${when(k.expires)}</td>
      <td>${dash(k.created_by)}</td>
      <td>${when(k.created)}</td>
      <td class="num"><div class="row-actions">
        <a class="btn btn-sm" href="/admin/print?ids=${encodeURIComponent(k.id)}" target="_blank" rel="noopener">Slip</a>
        ${k.mac && !k.shared ? `<button class="btn btn-sm" data-reset="${h(k.id)}" data-label="${h(k.label)}">Reset</button>` : ''}
        <button class="btn btn-sm btn-danger" data-revoke="${h(k.id)}" data-label="${h(k.label)}">End</button>
      </div></td>
    </tr>`,
    )
    .join('')}</tbody></table></div>`;
}

function bindKeyActions(root, after) {
  for (const btn of $$('[data-revoke]', root)) {
    btn.onclick = async () => {
      if (!confirm(`Remove the key for “${btn.dataset.label}”? The device using it is disconnected and can't reconnect with it.`)) return;
      btn.disabled = true;
      try {
        await api(`/keys/${encodeURIComponent(btn.dataset.revoke)}/revoke`, { method: 'POST', body: {} });
        toast('Key removed');
        after();
      } catch (err) {
        btn.disabled = false;
        toast(err.message);
      }
    };
  }
  for (const btn of $$('[data-reset]', root)) {
    btn.onclick = async () => {
      if (!confirm(`Free the key for “${btn.dataset.label}” so another device can use it? The key itself stays the same.`)) return;
      btn.disabled = true;
      try {
        await api(`/keys/${encodeURIComponent(btn.dataset.reset)}/reset`, { method: 'POST', body: {} });
        toast('Key reset. The next device that connects with it keeps it.');
        after();
      } catch (err) {
        btn.disabled = false;
        toast(err.message);
      }
    };
  }
}

/* ---------- overview ---------- */

function healthChecks(hl) {
  const items = [];
  const r = hl.radius;
  if (r?.lastAccept) items.push(['ok', `Logins are working on ${me.schoolSsid}`, `Last successful login ${ago(r.lastAccept)}.`]);
  if (r?.lastAccounting) items.push(['ok', 'Usage reports are arriving', `Last accounting update ${ago(r.lastAccounting)}.`]);
  else if (r?.lastAccept) items.push(['warn', 'No usage reports yet', 'Add a RADIUS accounting service (port 1813) to the Nexus WLAN on the vSZ to see data used per person.']);
  else if (r?.lastRequest) items.push(['warn', `No successful logins on ${me.schoolSsid} yet`, `FreeRADIUS last asked ${ago(r.lastRequest)}. Check Activity for why logins were turned away.`]);
  else items.push(['warn', 'FreeRADIUS hasn’t called yet', 'Expected after the first login attempt. If people can’t connect, check the FreeRADIUS container and its logs.']);

  if (!hl.directory) items.push(['warn', 'Directory lookup is off', 'Org-unit rules and suspended-account checks need it. Turn on google.directory in config.json.']);

  // A failure an admin has acknowledged is hidden; one that happens again shows again.
  const fresh = (t) => !hl.acknowledgedAt || t > hl.acknowledgedAt;
  const v = hl.vsz;
  if (v.lastError && (!v.lastOk || v.lastErrorAt > v.lastOk) && fresh(v.lastErrorAt)) items.push(['bad', "The vSZ API isn't answering", `${v.lastError} (${ago(v.lastErrorAt)}). Guest keys can't be made or removed.`]);
  else if (v.lastOk) items.push(['ok', 'The vSZ API is answering', `For guest SSID keys. Last call ${ago(v.lastOk)}.`]);
  if (v.security === 'unverified') items.push(['warn', "The vSZ certificate isn't checked", 'Run npm run vsz:fingerprint and set dpsk.tlsFingerprint.']);

  const b = hl.backup;
  if (b?.error && fresh(b.at)) items.push(['bad', 'The last backup failed', `${b.error} (${ago(b.at)})`]);
  else if (b && !b.error) items.push(['ok', `Backed up ${ago(b.at)}`, `${String(b.file).split(/[\\/]/).pop()}, ${Math.round(b.size / 1024)} KB.`]);
  if (b?.offsite?.error && fresh(b.offsite.at)) items.push(['bad', "The backup couldn't be copied to Google Drive", `${b.offsite.error} (${ago(b.offsite.at)}). The copy on the server is fine.`]);
  else if (b?.offsite?.name && !b.offsite.error) items.push(['ok', 'Copied to Google Drive', `${b.offsite.name}, ${Math.round(b.offsite.size / 1024)} KB, ${ago(b.offsite.at)}.`]);
  if (hl.alerts && !hl.alerts.enabled) items.push(['warn', 'Email alerts are off', 'Set alerts.from and alerts.to in config.json so IT hears about problems straight away.']);

  const latest = hl.recentErrors[0];
  if (latest) {
    const d = latest.detail ?? {};
    items.push(['bad', `Latest problem: ${TYPE_LABEL[latest.type] ?? latest.type.replace(/_/g, ' ')}`, `${d.error ?? d.message ?? eventDetail(latest)} · ${ago(latest.time)}`, true]);
  }
  return items
    .map(
      ([tone, title, text, link]) => `<li>${checkIcon(tone)}<div><strong>${h(title)}</strong><p>${h(text)}</p>${
        link ? '<p><a href="#activity" data-category="error">See all problems</a></p>' : ''
      }</div></li>`,
    )
    .join('');
}

async function overview() {
  const d = await api('/overview');
  if (!location.hash.match(/^(#overview)?$/)) return;
  const t = d.today;
  const checks = healthChecks(d.health);
  view.innerHTML = `
  <div class="page-head">
    <div><h1>Overview</h1><p class="muted">Today on ${h(me.schoolSsid)} and ${h(me.guestSsid)} · updates every 30 seconds</p></div>
    <div class="actions"><button class="btn" id="refresh">Refresh</button></div>
  </div>
  <div class="kpis">
    ${kpi('People logged in today', t.people, `${num(t.devices)} ${t.devices === 1 ? 'device' : 'devices'}`)}
    ${kpi('Online now', d.online, `${h(bytes(d.usageToday.down + d.usageToday.up))} used today`)}
    ${kpi('Turned away today', t.denied, 'Wrong password, blocked or no rule')}
    ${kpi('Problems in 24 hours', d.errors24h, d.errors24h ? badge('bad', 'Needs a look') : badge('ok', 'All clear'))}
  </div>
  <div class="stack">
    <section class="panel"><div class="panel-head"><div><h2>Health</h2>${
      d.acknowledged ? `<p class="muted">Problems up to ${h(when(d.acknowledged.at))} acknowledged by ${h(d.acknowledged.by)}. They're still in Activity.</p>` : ''
    }</div>${
      checks.includes('class="icon bad"') || d.errors24h
        ? '<div class="actions"><button class="btn" id="ack-problems" type="button">Acknowledge all</button></div>'
        : ''
    }</div><ul class="checks">${checks}</ul></section>
    <section class="panel">
      <div class="panel-head"><div><h2>Latest logins</h2><p class="muted">Devices that logged in to ${h(me.schoolSsid)} most recently</p></div></div>
      ${devicesTable(d.recentLogins)}
    </section>
  </div>`;
  $('#refresh').onclick = () => overview().then(() => toast('Up to date'));
  const ackBtn = $('#ack-problems');
  if (ackBtn) {
    ackBtn.onclick = async () => {
      ackBtn.disabled = true;
      try {
        await api('/problems/acknowledge', { method: 'POST', body: {} });
        clearTimeout(refreshTimer);
        await overview();
        toast('Problems acknowledged. New ones will show again.');
      } catch (err) {
        ackBtn.disabled = false;
        toast(err.message);
      }
    };
  }
  refreshTimer = setTimeout(overview, 30_000);
}

/* ---------- activity ---------- */

const activityState = { category: '', q: '' };

function eventRows(events, { withPerson = true } = {}) {
  return events
    .map(
      (e) => `<tr>
      <td>${when(e.time)}</td>
      <td>${eventBadge(e)}</td>
      ${withPerson ? `<td>${personLink(e.email)}</td>` : ''}
      <td class="mono">${dash(e.mac)}</td>
      <td>${h(eventDetail(e))}</td>
    </tr>`,
    )
    .join('');
}

function eventsTable(events, opts = {}) {
  const withPerson = opts.withPerson ?? true;
  if (!events.length) return '<p class="empty">Nothing here yet.</p>';
  return `<div class="table-wrap"><table class="data"><thead><tr>
    <th>When</th><th>What</th>${withPerson ? '<th>Who</th>' : ''}<th>Device</th><th>Details</th>
  </tr></thead><tbody>${eventRows(events, { withPerson })}</tbody></table></div>`;
}

async function activity() {
  const filters = [
    ['', 'Everything'],
    ['signin', 'Logins'],
    ['denied', 'Turned away'],
    ['usage', 'High usage'],
    ['keys', 'Guest SSID'],
    ['error', 'Problems'],
    ['admin', 'Admin'],
  ];
  view.innerHTML = `
  <div class="page-head"><div><h1>Activity</h1><p class="muted">Everything the platform has recorded, newest first. Logins show once per device per day.</p></div></div>
  <section class="panel">
    <div class="toolbar">
      <div class="chips" role="group" aria-label="Show">${filters
        .map(([v, l]) => `<button type="button" class="chip" data-category="${v}" aria-pressed="${activityState.category === v}">${l}</button>`)
        .join('')}</div>
      <input type="search" class="search" id="q" placeholder="Search email, device or text" value="${h(activityState.q)}" aria-label="Search activity">
    </div>
    <div id="events"></div>
    <div class="panel-body" id="more-wrap" hidden><button class="btn btn-block" id="more">Show older</button></div>
  </section>`;

  let oldest = null;
  async function load(append = false) {
    const p = new URLSearchParams();
    if (activityState.category) p.set('category', activityState.category);
    if (activityState.q) p.set('q', activityState.q);
    if (append && oldest) p.set('before', oldest);
    const events = await api(`/events?${p}`);
    if (append) $('#events tbody')?.insertAdjacentHTML('beforeend', eventRows(events));
    else $('#events').innerHTML = eventsTable(events);
    if (events.length) oldest = events.at(-1).id;
    $('#more-wrap').hidden = events.length < 50;
  }

  for (const chip of $$('.chip', view)) {
    chip.onclick = () => {
      activityState.category = chip.dataset.category;
      for (const c of $$('.chip', view)) c.setAttribute('aria-pressed', c === chip);
      load();
    };
  }
  let t;
  $('#q').oninput = (e) => {
    clearTimeout(t);
    t = setTimeout(() => {
      activityState.q = e.target.value.trim();
      load();
    }, 250);
  };
  $('#more').onclick = () => load(true);
  await load();
}

/* ---------- people ---------- */

async function people() {
  view.innerHTML = `
  <div class="page-head"><div><h1>People</h1><p class="muted">Everyone who has logged in to ${h(me.schoolSsid)} or been turned away</p></div></div>
  <div class="stack">
    <section class="panel">
      <div class="toolbar">
        <input type="search" class="search" id="q" placeholder="Search by email or device MAC" aria-label="Search people">
      </div>
      <div id="list"></div>
    </section>
    <section class="panel">
      <div class="panel-head"><div><h2>Blocked</h2><p class="muted">Blocked people are turned away at their next login, even with the right password</p></div></div>
      <div id="blocked"></div>
      <form class="panel-body field-row" id="block-form">
        <div class="field"><label for="b-email">Block someone</label><input type="text" id="b-email" placeholder="name@phahs.org.za" autocomplete="off" required></div>
        <div class="field"><label for="b-reason">Reason</label><input type="text" id="b-reason" placeholder="Optional. They see it when they try to sign in." maxlength="200"></div>
        <div class="field"><span class="label">&nbsp;</span><button class="btn btn-danger" type="submit">Block</button></div>
      </form>
    </section>
  </div>`;

  async function load(q = '') {
    const data = await api(`/people${q ? `?q=${encodeURIComponent(q)}` : ''}`);
    $('#list').innerHTML = data.people.length
      ? `<div class="table-wrap"><table class="data"><thead><tr>
          <th>Person</th><th>Last seen</th><th class="num">Devices</th><th class="num">Logins</th><th class="num">Turned away</th><th>Status</th>
        </tr></thead><tbody>${data.people
          .map(
            (p) => `<tr>
            <td>${personLink(p.email)}</td>
            <td>${when(p.last)}</td>
            <td class="num">${num(p.devices)}</td>
            <td class="num">${num(p.logins)}</td>
            <td class="num">${num(p.denied)}</td>
            <td>${p.blocked ? badge('bad', 'Blocked') : badge('ok', 'Allowed')}</td>
          </tr>`,
          )
          .join('')}</tbody></table></div>`
      : `<p class="empty">${q ? 'No one matches that search.' : 'No one has logged in yet.'}</p>`;
    $('#blocked').innerHTML = data.blocked.length
      ? `<div class="table-wrap"><table class="data"><thead><tr><th>Person</th><th>Reason</th><th>Blocked</th><th></th></tr></thead><tbody>${data.blocked
          .map(
            (b) => `<tr>
            <td>${personLink(b.email)}</td>
            <td>${dash(b.reason)}</td>
            <td>${when(b.at)}<span class="sub">by ${h(b.blocked_by)}</span></td>
            <td class="num"><button class="btn btn-sm" data-unblock="${h(b.email)}">Unblock</button></td>
          </tr>`,
          )
          .join('')}</tbody></table></div>`
      : '<p class="empty">No one is blocked.</p>';
    for (const btn of $$('[data-unblock]', view)) {
      btn.onclick = async () => {
        await api(`/people/${encodeURIComponent(btn.dataset.unblock)}/unblock`, { method: 'POST', body: {} });
        toast(`${btn.dataset.unblock} unblocked`);
        load($('#q').value.trim());
      };
    }
  }

  let t;
  $('#q').oninput = (e) => {
    clearTimeout(t);
    t = setTimeout(() => load(e.target.value.trim()), 250);
  };
  $('#block-form').onsubmit = async (e) => {
    e.preventDefault();
    const email = $('#b-email').value.trim().toLowerCase();
    try {
      await api(`/people/${encodeURIComponent(email)}/block`, { method: 'POST', body: { reason: $('#b-reason').value } });
      toast(`${email} blocked`);
      e.target.reset();
      load($('#q').value.trim());
    } catch (err) {
      toast(err.message);
    }
  };
  await load();
}

async function person(email) {
  const p = await api(`/people/${encodeURIComponent(email)}`);
  const b = p.blocked;
  view.innerHTML = `
  <a class="back" href="#people">${ICON.back}People</a>
  <div class="page-head">
    <div class="person-head">
      <div class="avatar" aria-hidden="true">${h(p.email[0])}</div>
      <div><h1>${h(p.email)}</h1><p>${b ? badge('bad', 'Blocked') : badge('ok', 'Allowed')}</p></div>
    </div>
    <div class="actions">
      ${b ? '<button class="btn" id="unblock">Unblock</button>' : '<button class="btn btn-danger" id="block">Block</button>'}
    </div>
  </div>
  <form class="panel panel-body field-row mb" id="block-form" hidden>
    <div class="field"><label for="reason">Why are you blocking ${h(p.email)}?</label><input type="text" id="reason" maxlength="200" placeholder="Optional. They see it when they try to sign in."></div>
    <div class="field"><span class="label">&nbsp;</span><div class="actions"><button class="btn btn-danger" type="submit">Block</button><button class="btn" type="button" id="cancel">Cancel</button></div></div>
  </form>
  ${
    b
      ? `<div class="notice notice-warn mb">Blocked ${h(ago(b.at))} by ${h(b.blocked_by)}${b.reason ? ` — “${h(b.reason)}”` : ''}. They're turned away at their next login. A device that's connected now stays on until it logs in again (within ${h(me.sessionHours)} hours), or until you change their Google password.</div>`
      : ''
  }
  <div class="stack">
    <section class="panel"><div class="panel-head"><div><h2>Devices</h2><p class="muted">Every device that has logged in with this account</p></div></div>${devicesTable(p.devices, { withPerson: false, empty: 'No logins yet.' })}</section>
    ${personUsageSection(p.usage)}
    <section class="panel"><div class="panel-head"><h2>History</h2><p class="muted">Latest 100 events</p></div>${eventsTable(p.events, { withPerson: false })}</section>
  </div>`;

  sizeBars(view);
  const form = $('#block-form');
  if ($('#block')) {
    $('#block').onclick = () => {
      form.hidden = false;
      $('#reason').focus();
    };
  }
  $('#cancel').onclick = () => (form.hidden = true);
  form.onsubmit = async (e) => {
    e.preventDefault();
    await api(`/people/${encodeURIComponent(p.email)}/block`, { method: 'POST', body: { reason: $('#reason').value } });
    toast(`${p.email} blocked`);
    person(p.email);
  };
  if ($('#unblock')) {
    $('#unblock').onclick = async () => {
      await api(`/people/${encodeURIComponent(p.email)}/unblock`, { method: 'POST', body: {} });
      toast(`${p.email} unblocked`);
      person(p.email);
    };
  }
}

function personUsageSection(u) {
  const days = u.daily;
  const maxDay = Math.max(0, ...days.map((d) => d.down + d.up));
  const total = days.reduce((s, d) => s + d.down + d.up, 0);
  const open = u.sessions.filter((s) => !s.stopped);
  return `<section class="panel"><div class="panel-head"><div><h2>Data used</h2><p class="muted">Last 30 days: ${h(bytes(total))}${open.length ? ` · online now on ${open.length} ${open.length === 1 ? 'device' : 'devices'}` : ''}</p></div></div>
    ${
      days.length
        ? `<div class="table-wrap"><table class="data compact"><thead><tr><th>Day</th><th>Total</th><th class="num">Downloaded</th><th class="num">Uploaded</th></tr></thead><tbody>${days
            .map((d) => `<tr><td>${h(new Date(`${d.day}T12:00:00`).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short' }))}</td><td>${usageCell(d.down + d.up, maxDay)}</td><td class="num">${h(bytes(d.down))}</td><td class="num">${h(bytes(d.up))}</td></tr>`)
            .join('')}</tbody></table></div>`
        : '<p class="empty">No usage reported yet.</p>'
    }
    ${
      u.sessions.length
        ? `<div class="panel-head"><h3>Sessions</h3></div><div class="table-wrap"><table class="data compact"><thead><tr><th>Device</th><th>IP</th><th>Started</th><th>Length</th><th class="num">Downloaded</th><th class="num">Uploaded</th><th>Status</th></tr></thead><tbody>${u.sessions
            .map((s) => `<tr><td class="mono">${h(s.mac)}</td><td class="mono">${dash(s.ip)}</td><td>${when(s.started)}</td><td>${h(duration((s.stopped ?? s.updated) - s.started))}</td><td class="num">${h(bytes(s.bytes_down))}</td><td class="num">${h(bytes(s.bytes_up))}</td><td>${s.stopped ? '<span class="badge">Ended</span>' : badge('ok', 'Online')}</td></tr>`)
            .join('')}</tbody></table></div>`
        : ''
    }
  </section>`;
}

/* ---------- usage ---------- */

const usageState = { period: 'today' };

async function usage() {
  const d = await api(`/usage?period=${usageState.period}`);
  if (!location.hash.startsWith('#usage')) return;
  const label = { today: 'Today', week: 'Last 7 days', month: 'Last 30 days' }[d.period];
  const maxTop = Math.max(0, ...d.top.map((r) => r.down + r.up));
  const maxVlan = Math.max(0, ...d.byVlan.map((r) => r.down + r.up));
  const over = d.alertGb ? d.top.filter((r) => r.down + r.up >= d.alertGb * 1024 ** 3).length : 0;
  view.innerHTML = `
  <div class="page-head">
    <div><h1>Usage</h1><p class="muted">Data used on the WiFi, from the vSZ's accounting reports${d.accounting ? ` · last report ${h(ago(d.accounting))}` : ''}. Shows how much, not which sites.</p></div>
    <div class="chips" role="group" aria-label="Period">${['today', 'week', 'month']
      .map((p) => `<button type="button" class="chip" data-period="${p}" aria-pressed="${d.period === p}">${{ today: 'Today', week: '7 days', month: '30 days' }[p]}</button>`)
      .join('')}</div>
  </div>
  <div class="kpis">
    ${kpiText(`Downloaded · ${label}`, bytes(d.totals.down), `${num(d.totals.people)} people`)}
    ${kpiText(`Uploaded · ${label}`, bytes(d.totals.up), 'From devices to the internet')}
    ${kpi('Online now', d.online.length, `${num(new Set(d.online.map((o) => o.who)).size)} people`)}
    ${kpi(`Over ${d.alertGb ?? '–'} GB`, over, d.alertGb ? 'People past the daily alert level in this period' : 'Set an alert level in Settings')}
  </div>
  <div class="stack">
    <section class="panel">
      <div class="panel-head"><div><h2>Top users · ${h(label)}</h2><p class="muted">The 50 people who used the most data</p></div><a class="btn btn-sm" href="/admin/api/export/usage.csv">Download CSV</a></div>
      ${
        d.top.length
          ? `<div class="table-wrap"><table class="data compact"><thead><tr><th>Person</th><th>Total</th><th class="num">Downloaded</th><th class="num">Uploaded</th><th class="num">Devices</th></tr></thead><tbody>${d.top
              .map((r) => `<tr><td>${who(r.who)}</td><td>${usageCell(r.down + r.up, maxTop)}</td><td class="num">${h(bytes(r.down))}</td><td class="num">${h(bytes(r.up))}</td><td class="num">${num(r.devices)}</td></tr>`)
              .join('')}</tbody></table></div>`
          : '<p class="empty">No usage reported in this period yet.</p>'
      }
    </section>
    <section class="panel">
      <div class="panel-head"><div><h2>By VLAN · ${h(label)}</h2></div></div>
      ${
        d.byVlan.length
          ? `<div class="table-wrap"><table class="data compact"><thead><tr><th>VLAN</th><th>Total</th><th class="num">Downloaded</th><th class="num">Uploaded</th><th class="num">People</th></tr></thead><tbody>${d.byVlan
              .map((r) => `<tr><td>${r.vlan_id ? num(r.vlan_id) : '<span class="faint">Default / guest</span>'}</td><td>${usageCell(r.down + r.up, maxVlan)}</td><td class="num">${h(bytes(r.down))}</td><td class="num">${h(bytes(r.up))}</td><td class="num">${num(r.people)}</td></tr>`)
              .join('')}</tbody></table></div>`
          : '<p class="empty">Nothing yet.</p>'
      }
    </section>
    <section class="panel">
      <div class="panel-head"><div><h2>Online now</h2><p class="muted">Sessions the vSZ reported in the last ${h(me.staleMinutes)} minutes</p></div></div>
      ${
        d.online.length
          ? `<div class="table-wrap"><table class="data compact"><thead><tr><th>Who</th><th>Device</th><th>IP</th><th>VLAN</th><th>Connected</th><th class="num">This session</th></tr></thead><tbody>${d.online
              .map((o) => `<tr><td>${who(o.who)}</td><td class="mono">${h(o.mac)}</td><td class="mono">${dash(o.ip)}</td><td>${vlan(o.vlan_id)}</td><td>${when(o.started)}</td><td class="num">${h(bytes(o.bytes_down + o.bytes_up))}</td></tr>`)
              .join('')}</tbody></table></div>`
          : '<p class="empty">No one is online right now, or accounting isn\'t set up on the vSZ yet.</p>'
      }
    </section>
  </div>`;
  for (const chip of $$('[data-period]', view)) {
    chip.onclick = () => {
      usageState.period = chip.dataset.period;
      usage();
    };
  }
  sizeBars(view);
  refreshTimer = setTimeout(usage, 60_000);
}

/* ---------- guests ---------- */

async function guests() {
  const rows = await api('/guests');
  view.innerHTML = `
  <div class="page-head"><div><h1>Guests</h1><p class="muted">Keys for visitors on ${h(me.guestSsid)}${me.guestVlanId ? ` (VLAN ${num(me.guestVlanId)})` : ''}. A key works on one device, or on several for a group or event, and ends on its last day.</p></div></div>
  <div class="stack">
    <section class="panel">
      <div class="panel-head"><div><h2>Make a guest key</h2><p class="muted">Opens a slip to print or show the visitor</p></div></div>
      <form class="panel-body field-row" id="guest-form">
        <div class="field"><label for="g-name">Visitor's name</label><input type="text" id="g-name" maxlength="40" placeholder="e.g. Mrs Botha, exam moderator" required></div>
        <div class="field"><label for="g-days">For how many days</label><input type="number" id="g-days" min="1" max="${h(me.maxGuestDays)}" value="1" required></div>
        <div class="field"><label for="g-shared">Devices</label><select id="g-shared"><option value="one">One device</option><option value="shared">Several devices (a group or event)</option></select></div>
        <div class="field"><span class="label">&nbsp;</span><button class="btn btn-primary" type="submit">Make key and print</button></div>
      </form>
    </section>
    <section class="panel"><div class="panel-head"><h2>Active guest keys</h2></div>${keysTable(rows, { empty: 'No guest keys right now.' })}</section>
  </div>`;
  bindKeyActions(view, guests);
  $('#guest-form').onsubmit = async (e) => {
    e.preventDefault();
    try {
      const r = await api('/guests', { method: 'POST', body: { name: $('#g-name').value, days: Number($('#g-days').value), shared: $('#g-shared').value === 'shared' } });
      window.open(`/admin/print?ids=${encodeURIComponent(r.id)}`, '_blank', 'noopener');
      guests();
    } catch (err) {
      toast(err.message);
    }
  };
}

/* ---------- rules ---------- */

let draft = null;
let saved = null;
let directoryOn = false;

function problemsNotice(problems) {
  return `<div class="notice notice-bad"><strong>Not saved.</strong><ul>${problems.map((p) => `<li>${h(p)}</li>`).join('')}</ul></div>`;
}

function vlanField(prefix, src) {
  return `<div class="field-row">
    <div class="field"><label for="${prefix}-vlan">VLAN</label><input type="number" min="1" max="4094" step="1" id="${prefix}-vlan" data-k="vlanId" value="${h(src.vlanId ?? '')}" placeholder="SSID default"><span class="hint">The VLAN their devices join. Leave empty for the SSID's own VLAN.</span></div>
  </div>`;
}

function ruleCard(r, i, total) {
  return `<article class="rule" data-i="${i}">
    <div class="rule-head">
      <span class="rule-order">${i + 1}</span>
      <div class="field"><input type="text" data-k="name" value="${h(r.name)}" placeholder="Rule name, e.g. Staff" aria-label="Rule ${i + 1} name" maxlength="40"></div>
      <button type="button" class="icon-btn" data-move="-1" ${i === 0 ? 'disabled' : ''} aria-label="Move up">${ICON.up}</button>
      <button type="button" class="icon-btn" data-move="1" ${i === total - 1 ? 'disabled' : ''} aria-label="Move down">${ICON.down}</button>
      <button type="button" class="icon-btn" data-remove aria-label="Delete rule">${ICON.trash}</button>
    </div>
    <div class="rule-body">
      <div class="field-row">
        <div class="field"><label for="r${i}-ou">In org unit</label><input type="text" id="r${i}-ou" data-k="orgUnit" value="${h(r.orgUnit ?? '')}" placeholder="${directoryOn ? 'e.g. /Students' : 'Needs the directory lookup'}" ${directoryOn ? '' : 'disabled'}><span class="hint">${directoryOn ? 'Includes the org units inside it' : 'Turn on google.directory in config.json to use this'}</span></div>
        <div class="field"><label for="r${i}-email">Email matches</label><input type="text" class="mono" id="r${i}-email" data-k="email" value="${h(r.email ?? '')}" placeholder="e.g. ^(exam|shared)\\."><span class="hint">Optional regular expression. Empty matches any email.</span></div>
      </div>
      <div class="field"><span class="label">Then</span>
        <div class="segmented" role="group" aria-label="Rule ${i + 1} outcome">
          <button type="button" data-deny="0" aria-pressed="${!r.deny}">Let them on</button>
          <button type="button" data-deny="1" aria-pressed="${Boolean(r.deny)}">Turn them away</button>
        </div>
      </div>
      ${
        r.deny
          ? `<div class="field"><label for="r${i}-msg">Message</label><input type="text" id="r${i}-msg" data-k="message" value="${h(r.message ?? '')}" maxlength="200" placeholder="This account can't use the school WiFi."><span class="hint">Recorded in Activity; some devices show it too.</span></div>`
          : vlanField(`r${i}`, r)
      }
    </div>
  </article>`;
}

function renderRules(problems = null) {
  const pol = draft.policy;
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved);
  const fallbackDeny = pol.default === null;
  view.innerHTML = `
  <div class="page-head"><div><h1>Rules</h1><p class="muted">Which school accounts may log in to ${h(me.schoolSsid)}, and the VLAN each group lands on. Changes apply at each device's next login.</p></div></div>
  <div class="stack">
    <section class="panel">
      <div class="panel-head"><div><h2>Google Workspace domains</h2><p class="muted">Other domains and personal Gmail are always turned away. People can log in with just their username; the first domain is added.</p></div></div>
      <div class="panel-body field"><label for="domains" class="label">One domain per line</label><textarea id="domains" class="short" rows="2">${h(draft.allowedDomains.join('\n'))}</textarea></div>
    </section>
    <section class="panel">
      <div class="panel-head"><div><h2>Rules</h2><p class="muted">Checked from top to bottom. The first rule that matches someone decides.</p></div><button class="btn btn-sm" id="add-rule">Add rule</button></div>
      <div class="panel-body" id="rule-list">${pol.rules.length ? pol.rules.map((r, i) => ruleCard(r, i, pol.rules.length)).join('') : '<p class="muted">No rules yet. Everyone from the domains above gets the setting below.</p>'}</div>
    </section>
    <section class="panel" id="fallback">
      <div class="panel-head"><div><h2>Everyone else</h2><p class="muted">People from your domains that no rule matched</p></div></div>
      <div class="panel-body rule-body">
        <div class="segmented" role="group" aria-label="Everyone else">
          <button type="button" data-fallback="allow" aria-pressed="${!fallbackDeny}">Let them on</button>
          <button type="button" data-fallback="deny" aria-pressed="${fallbackDeny}">Turn them away</button>
        </div>
        ${fallbackDeny ? '' : vlanField('fb', pol.default ?? {})}
      </div>
    </section>
  </div>
  <div class="savebar">
    <div>${problems ? problemsNotice(problems) : `<span class="muted">${dirty ? 'You have unsaved changes' : 'All changes saved'}</span>`}</div>
    <div class="actions"><button class="btn" id="discard" ${dirty ? '' : 'disabled'}>Discard</button><button class="btn btn-primary" id="save" ${dirty ? '' : 'disabled'}>Save rules</button></div>
  </div>`;
  bindRules();
}

const readValue = (input) => {
  const v = input.value.trim();
  if (input.dataset.k === 'vlanId') return v === '' ? undefined : Math.round(Number(v));
  return v || undefined;
};

function markDirty() {
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved);
  $('#save').disabled = !dirty;
  $('#discard').disabled = !dirty;
  $('.savebar > div:first-child').innerHTML = `<span class="muted">${dirty ? 'You have unsaved changes' : 'All changes saved'}</span>`;
}

function bindRules() {
  const pol = draft.policy;
  $('#domains').oninput = (e) => {
    draft.allowedDomains = e.target.value.split(/[\s,]+/).filter(Boolean);
    markDirty();
  };
  for (const card of $$('.rule', view)) {
    const i = Number(card.dataset.i);
    for (const input of $$('input[data-k]', card)) {
      input.oninput = () => {
        const v = readValue(input);
        if (v === undefined) delete pol.rules[i][input.dataset.k];
        else pol.rules[i][input.dataset.k] = v;
        markDirty();
      };
    }
    for (const btn of $$('[data-deny]', card)) {
      btn.onclick = () => {
        if (btn.dataset.deny === '1') pol.rules[i].deny = true;
        else delete pol.rules[i].deny;
        renderRules();
      };
    }
    $('[data-remove]', card).onclick = () => {
      pol.rules.splice(i, 1);
      renderRules();
    };
    for (const btn of $$('[data-move]', card)) {
      btn.onclick = () => {
        const j = i + Number(btn.dataset.move);
        [pol.rules[i], pol.rules[j]] = [pol.rules[j], pol.rules[i]];
        renderRules();
      };
    }
  }
  $('#add-rule').onclick = () => {
    pol.rules.push({ name: '' });
    renderRules();
    $$('.rule input[data-k="name"]', view).at(-1).focus();
  };
  for (const btn of $$('[data-fallback]', view)) {
    btn.onclick = () => {
      pol.default = btn.dataset.fallback === 'deny' ? null : {};
      renderRules();
    };
  }
  for (const input of $$('#fallback input[data-k]', view)) {
    input.oninput = () => {
      pol.default ??= {};
      const v = readValue(input);
      if (v === undefined) delete pol.default[input.dataset.k];
      else pol.default[input.dataset.k] = v;
      markDirty();
    };
  }
  $('#discard').onclick = () => {
    draft = structuredClone(saved);
    renderRules();
  };
  $('#save').onclick = async () => {
    $('#save').disabled = true;
    try {
      const s = await api('/settings', { method: 'POST', body: { allowedDomains: draft.allowedDomains, policy: draft.policy } });
      loadRuleState(s);
      renderRules();
      toast('Rules saved');
    } catch (err) {
      renderRules(err.problems?.length ? err.problems : [err.message]);
    }
  };
}

function loadRuleState(s) {
  directoryOn = s.fixed.directory;
  saved = { allowedDomains: s.allowedDomains, policy: { rules: s.policy.rules, default: s.policy.default === undefined ? {} : s.policy.default } };
  draft = structuredClone(saved);
}

async function rules() {
  loadRuleState(await api('/settings'));
  renderRules();
}

/* ---------- settings ---------- */

async function settings(s) {
  s ??= await api('/settings');
  const f = s.fixed;
  const security = {
    pinned: badge('ok', 'Certificate pinned'),
    verified: badge('ok', 'Certificate verified'),
    unverified: badge('warn', 'Certificate not checked'),
    'plain-http': badge('warn', 'Not encrypted'),
  }[f.vszSecurity];
  view.innerHTML = `
  <div class="page-head"><div><h1>Settings</h1><p class="muted">How the platform is set up</p></div></div>
  <div class="stack">
    <section class="panel">
      <div class="panel-head"><div><h2>Name</h2><p class="muted">Shown on guest key slips and in this dashboard</p></div></div>
      <form class="panel-body field-row" id="name-form">
        <div class="field"><label for="b-name">Network name</label><input type="text" id="b-name" value="${h(s.branding.name)}" maxlength="60" required></div>
        <div class="field"><span class="label">&nbsp;</span><div><button class="btn" type="submit">Save</button></div></div>
      </form>
    </section>

    <section class="panel">
      <div class="panel-head"><div><h2>Usage alert</h2><p class="muted">Email IT (and note it in Activity) when someone uses more than this in one day</p></div></div>
      <form class="panel-body field-row" id="usage-form">
        <div class="field"><label for="usage-gb">Daily alert level (GB)</label><input type="number" id="usage-gb" min="0.1" max="10000" step="0.1" value="${h(s.usageAlertGb ?? '')}" placeholder="Off"><span class="hint">Leave empty to turn it off. Each person triggers it at most once a day.</span></div>
        <div class="field"><span class="label">&nbsp;</span><div><button class="btn" type="submit">Save</button></div></div>
      </form>
    </section>

    <section class="panel">
      <div class="panel-head"><div><h2>Records</h2><p class="muted">Logins and usage hold personal information (email, device address, data used), so keep them only as long as you need</p></div></div>
      <form class="panel-body field-row" id="ret-form">
        <div class="field"><label for="ret">Keep records for (days)</label><input type="number" id="ret" min="7" max="3650" value="${h(s.retentionDays)}"><span class="hint">Older activity and device records are deleted automatically</span></div>
        <div class="field"><span class="label">&nbsp;</span><div><button class="btn" type="submit">Save</button></div></div>
      </form>
    </section>

    <section class="panel">
      <div class="panel-head"><div><h2>Platform</h2><p class="muted">Set in config.json and radius.env on the server</p></div></div>
      <div class="panel-body"><dl class="facts">
        <dt>School SSID</dt><dd><strong>${h(f.schoolSsid)}</strong>: Google username and password (WPA2-Enterprise, EAP-TTLS)</dd>
        <dt>Bare usernames</dt><dd>Get <span class="mono">@${h(f.defaultDomain)}</span> added</dd>
        <dt>Devices log in again every</dt><dd>${h(f.sessionHours)} hours, so blocks and rule changes reach connected devices by then</dd>
        <dt>Directory lookup</dt><dd>${f.directory ? badge('ok', 'On') : '<span class="badge">Off</span>'}</dd>
        <dt>Guest SSID</dt><dd><strong>${h(f.guestSsid)}</strong>: visitor keys (${f.guestVlanId ? `VLAN ${h(f.guestVlanId)}` : 'SSID default VLAN'}, up to ${h(f.maxGuestDays)} days)</dd>
        <dt>vSZ API</dt><dd><span class="mono">${h(f.vsz)}</span> ${security}</dd>
        <dt>Backups</dt><dd class="mono">${h(f.backup.dir)} <span class="muted">(last ${h(f.backup.keep)} days)</span></dd>
        <dt>Off-site</dt><dd>${f.backup.drive ? `Google Drive, as ${h(f.backup.drive.as)} <span class="muted">(last ${h(f.backup.drive.keep)})</span>` : '<span class="muted">Not set up: backups stay on this server</span>'}</dd>
        <dt>Email alerts</dt><dd>${f.alerts.enabled ? `To ${h(f.alerts.to.join(', '))}` : '<span class="badge">Off</span>'}</dd>
        <dt>Admins</dt><dd>${h(f.admins.join(', '))}</dd>
        <dt>Admin access from</dt><dd>${f.allowFrom.length ? h(f.allowFrom.join(', ')) : 'Anywhere'}</dd>
      </dl></div>
    </section>

    <section class="panel">
      <div class="panel-head"><div><h2>Tools</h2><p class="muted">Every action is recorded under Activity → Admin</p></div></div>
      <div class="panel-body stack">
        <div class="tool"><div><strong>Check connections</strong><p class="muted">Tries Google (directory and Secure LDAP), the vSZ and alert email, and sends a test alert.</p></div><button class="btn" id="check" type="button">Check</button></div>
        <ul class="checks" id="check-results" hidden></ul>
        <div class="tool"><div><strong>Connection guide</strong><p class="muted">A printable page for staff and learners: how to connect each device, and what the school records (POPIA).</p></div><a class="btn" href="/admin/guide" target="_blank" rel="noopener">Open</a></div>
        <div class="tool"><div><strong>Back up now</strong><p class="muted">A copy of the database is made every night; make one now before big changes.</p></div><button class="btn" id="backup-now" type="button">Back up</button></div>
        <div class="tool"><div><strong>Adopt keys from the vSZ</strong><p class="muted">After restoring a backup: guest keys on the vSZ that the platform doesn't know about are taken over.</p></div><button class="btn" id="adopt" type="button">Adopt keys</button></div>
        <div class="tool"><div><strong>Export usage</strong><p class="muted">Data used per person, device and day.</p></div><a class="btn" href="/admin/api/export/usage.csv">Download CSV</a></div>
        <div class="tool"><div><strong>Export logins</strong><p class="muted">Every person and device that has logged in, with VLAN and dates.</p></div><a class="btn" href="/admin/api/export/logins.csv">Download CSV</a></div>
        <div class="tool"><div><strong>Export guest keys</strong><p class="muted">Visitor keys with their VLAN, end date and bound device.</p></div><a class="btn" href="/admin/api/export/keys.csv">Download CSV</a></div>
      </div>
    </section>
  </div>`;

  const save = async (body, message) => {
    try {
      const next = await api('/settings', { method: 'POST', body });
      toast(message);
      settings(next);
    } catch (err) {
      toast(err.message);
    }
  };
  $('#name-form').onsubmit = (e) => {
    e.preventDefault();
    save({ branding: { name: $('#b-name').value } }, 'Name saved');
  };
  $('#usage-form').onsubmit = (e) => {
    e.preventDefault();
    const v = $('#usage-gb').value.trim();
    save({ usageAlertGb: v === '' ? null : Number(v) }, v === '' ? 'Usage alert turned off' : 'Usage alert saved');
  };
  $('#ret-form').onsubmit = (e) => {
    e.preventDefault();
    save({ retentionDays: Number($('#ret').value) }, 'Retention saved');
  };
  $('#check').onclick = async () => {
    const btn = $('#check');
    const list = $('#check-results');
    btn.disabled = true;
    btn.textContent = 'Checking…';
    try {
      const { results } = await api('/check', { method: 'POST', body: {} });
      const tone = (ok) => (ok === true ? 'ok' : ok === false ? 'bad' : 'info');
      list.innerHTML = results
        .map((r) => `<li>${checkIcon(tone(r.ok))}<div><strong>${h(r.name)}</strong><p>${h(r.detail)}</p></div></li>`)
        .join('');
      list.hidden = false;
    } catch (err) {
      toast(err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Check';
    }
  };
  $('#backup-now').onclick = async () => {
    try {
      const r = await api('/backup', { method: 'POST', body: {} });
      toast(`Backed up to ${String(r.file).split(/[\\/]/).pop()}`);
    } catch (err) {
      toast(err.message);
    }
  };
  $('#adopt').onclick = async () => {
    try {
      const r = await api('/adopt', { method: 'POST', body: {} });
      toast(`${r.adopted} keys adopted, ${r.skipped} left alone`);
    } catch (err) {
      toast(err.message);
    }
  };
}

/* ---------- start ---------- */

view.addEventListener('click', (e) => {
  const link = e.target.closest('a[data-category]');
  if (link) activityState.category = link.dataset.category;
});
$('#logout').onclick = async () => {
  await api('/logout', { method: 'POST', body: {} }).catch(() => {});
  location.href = '/admin';
};

me = await api('/me');
$('#me').textContent = me.email;
$('#avatar').textContent = me.email[0];
$('#network').textContent = me.network;
$('#school').textContent = me.school || me.network;
$('#motto').textContent = me.motto;
document.title = `${me.network} · WiFi admin`;
window.addEventListener('hashchange', route);
route();
