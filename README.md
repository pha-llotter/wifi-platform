# PHA WiFi: school Google sign-in for Ruckus SmartZone WiFi, with a network per group

People join an open school network, a sign-in page opens by itself, and they type their **school Google email and password**. Nothing to install, no certificates, no settings. Staff and learners use different networks, each on its own VLAN (for example **Nexus Staff** on VLAN 1 and **Nexus** on VLAN 10), and the platform only lets each person on to the network for their Google org unit. A device that has signed in is remembered, so it reconnects by itself for the rest of the term. Visitors without a school account use a small separate network, **Guest**, with keys made in the admin dashboard.

```
 device ──(1) joins Nexus (open Hotspot / WISPr WLAN)──▶ vSZ: "is this device remembered?" (MAC auth → RADIUS)
     remembered and still allowed → online at once. Otherwise:
 vSZ ──(2) redirects the browser──▶ https://wifi.phahs.org.za/?client_mac=…&uip=…&ssid=Nexus
 person ──(3) email + password──▶ platform ──▶ Google Secure LDAP: is the password right?
     platform checks: allowed domain · not blocked · Google directory: active, org unit · rules · right network
 platform ──(4) NBI Login(email, one-time ticket)──▶ vSZ :9443 ──RADIUS──▶ FreeRADIUS ──▶ platform: ticket valid?
 vSZ ──▶ device online on that network's VLAN; the platform remembers the device for portal.rememberDays
```

- **Why a form and not "Sign in with Google":** Google refuses its own sign-in page inside the "Log in to network" window that phones open, so a button would send people off to Safari or Chrome. A plain form works in that window on every device.
- **Passwords go to Google only.** The sign-in page sends the password straight to Google Secure LDAP to check, and never stores or logs it. The vSZ and RADIUS only ever see a one-time ticket that works once, for two minutes.
- **Bare usernames work.** `t.smith` becomes `t.smith@phahs.org.za`.
- **Changes reach remembered devices.** Each reconnect (and each session end, `radius.sessionTimeout`, 12 hours by default) asks the platform again, so blocks, suspensions, OU moves and rule changes apply at the next reconnect. Blocking someone also forgets their devices at once.
- **Data used per person.** The vSZ reports each session's bytes through RADIUS accounting, so the dashboard shows who's online and how much each person and device used. It shows the amount only, not which sites.
- **The admin dashboard** (`https://wifi.phahs.org.za/admin`) shows who signed in from which device and network, who was turned away and why, data used, the rules, blocks, guest keys, health, backups and alerts.

The PDF setup guide in [docs/](docs/) still describes the earlier 802.1X design for the school networks. Its parts 1–3 (server, firewall, Google) still apply; for the vSZ, follow this README.

## The parts

| Part | Runs | Does |
|---|---|---|
| **Platform** (`src/`) | Docker, on the platform server | The sign-in page, password checks with Google Secure LDAP, the hand-over to the vSZ (NBI), remembered devices, the admin dashboard, visitor keys on Guest via the vSZ API |
| **FreeRADIUS 3.2** (`deploy/freeradius`) | Docker, on the same server | Answers the vSZ's RADIUS: sign-ins and reconnects go to the platform (`/radius/portal`); accounting for the Usage page |
| **Caddy** | Docker, on the same server | HTTPS for the sign-in page and the dashboard |
| **Google Workspace** | Google | Secure LDAP for passwords, the Directory API for org units and status, OAuth for admin sign-in, optional Gmail alerts |
| **vSZ** | School | Nexus and Nexus Staff (Hotspot / WISPr, external portal, MAC auth), Guest (DPSK keys) |

## Setup

### 1. Server and DNS

A small Linux VPS with Docker; 1 vCPU and 1 GB RAM is plenty. Point two DNS **A records** at it:
- `wifi.phahs.org.za` for the dashboard;
- `radius.phahs.org.za` for the login certificate.

Firewall:

| Port | From | For |
|---|---|---|
| TCP 80, 443 | anywhere | Dashboard, and Let's Encrypt for both names |
| UDP 1812, 1813 | **the school's public IP only** | RADIUS from the vSZ |
| TCP 22 | your admin IPs | SSH |

### 2. Google Workspace (Education Fundamentals includes all of this)

1. **Secure LDAP client.** In the Admin console go to **Apps → LDAP → Add client**, for example "WiFi RADIUS".
   - Access permissions: **Verify user credentials** for the whole domain, and **Read user information** for the whole domain.
   - Download the **certificate** and save the `.crt` and `.key` as `/etc/wifi-portal/google-ldap/ldap-client.crt` and `ldap-client.key`.
   - Set the client's **Service status** to **On**.
   - Under **Access credentials**, click **Generate new credentials**. Some tenants let a certificate-only client see the org units but no users, so every login would fail. Put the username and password in `LDAP_IDENTITY` and `LDAP_PASSWORD` (radius.env) and in `google.ldap.identity` and `password` (config.json, for Check connections).
2. **OAuth client for admin sign-in.** In Google Cloud create a project, set **Google Auth Platform → Audience** to **Internal**, then create a **Web application** client with the redirect URI `https://wifi.phahs.org.za/admin/oauth/callback`. Put its ID and secret in `google.clientId` and `google.clientSecret`.
3. **Directory lookup** (org units, suspended accounts):
   - Enable the **Admin SDK API**.
   - Create a **service account** with no roles and a JSON key, saved as `/etc/wifi-portal/service-account.json`.
   - In **Security → API controls → Domain-wide delegation**, add its client ID with the scope `https://www.googleapis.com/auth/admin.directory.user.readonly`.
   - Set `google.directory.adminEmail` to an admin user.
4. **Alert emails** (optional). These are sent through the Gmail API, not SMTP, so there's no mail server or app password to set up.
   - In the same Cloud project, enable the **Gmail API**.
   - Add `https://www.googleapis.com/auth/gmail.send` to the service account's domain-wide delegation entry. The entry's scopes become `https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/gmail.send`.
   - Pick the mailbox alerts come from, for example `wifi-alerts@phahs.org.za`. It must be a real Workspace user, because the service account sends as that user. It can send only, and can't read mail.
   - Set `alerts.from` to that mailbox and `alerts.to` to the people who should hear about problems.
5. **Off-site backups** (recommended). Each nightly database copy is also uploaded, gzipped, to a Google Drive folder, so a lost server doesn't lose the records.
   - In the same Cloud project, enable the **Google Drive API**, and add `https://www.googleapis.com/auth/drive.file` to the delegation entry. With this scope the platform can only see files it uploaded itself.
   - Make a **Shared Drive** (for example "WiFi backups") and add the uploading user as **Content manager**. That user is `alerts.from` unless you set `backup.drive.as`.
   - Make a folder in it, and copy the last part of the folder's URL into `backup.drive.folderId`. The last 30 copies are kept (`backup.drive.keep`); older ones go to the Shared Drive's trash.

### 3. The vSZ and the school firewall

Menu names are for SmartZone 6.x/7.x.

1. **RADIUS services:** **Security → Authentication → Proxy (SZ Authenticator)**: a RADIUS service to the server's IP, port **1812**, with `RADIUS_SECRET` from radius.env. **Security → Accounting → Proxy**: the same server, port **1813**, same secret.
2. **The portal interface (NBI):** **System → General Settings → WISPr Northbound Interface**: enable it and set a password (`portal.nbi.password`). The platform logs devices in through it on TCP **9443**.
3. **The sign-in portal:** **Security → Hotspots & Portals → Hotspot (WISPr) → Create**:
   - Logon URL: **External**, redirect unauthenticated users to `https://wifi.phahs.org.za/`.
   - Start page: redirect to the URL the user wanted.
   - User session: timeout about **720 minutes**, grace period about **60 minutes**.
   - Walled garden: `wifi.phahs.org.za` only. Don't add Apple's or Google's captive-check hosts, or phones won't notice the sign-in page.
4. **The WLANs**, one per network in `portal.networks`, each with the same portal:
   - Authentication type **Hotspot (WISPr)**, method **Open**, encryption **None**.
   - Authentication and accounting services from step 1 (**Use the controller as proxy**), interim updates every **10 minutes**.
   - **Access VLAN**: that network's VLAN, exactly as in `portal.networks`.
   - **MAC authentication bypass** (in the Hotspot options): **on**. This is what lets remembered devices reconnect without the page.
   - **RADIUS options → Called Station ID**: a format that includes the SSID (for example **AP MAC:SSID**). The platform reads the network from it; without it, remembered devices see the page again each time.
   - Client isolation on, if you like.
5. **Guest:** a WPA2 WLAN with **Dynamic PSK** enabled, Keyboard-Friendly keys of 12–16 characters, expiration **Unlimited** (the platform ends guest keys itself). The platform needs a vSZ admin account with **WLAN** and **User/Device/App** full access.
6. **School firewall:** port-forward from the server's IP **only**: the vSZ API (`dpsk.port`, to vSZ 8443) and the NBI (`portal.nbi.port`, to vSZ 9443). Never open these to everyone.

### 4. Install

```bash
git clone https://github.com/pha-llotter/wifi-platform.git /opt/wifi-portal && cd /opt/wifi-portal
sudo mkdir -p /etc/wifi-portal/google-ldap /var/log/wifi-portal /var/lib/wifi-portal
sudo cp config.example.json /etc/wifi-portal/config.json               # fill in
sudo cp deploy/freeradius/radius.env.example /etc/wifi-portal/radius.env  # fill in
sudo chown 1000 /var/log/wifi-portal /var/lib/wifi-portal
```

Then copy in the Google files (step 2) and set permissions. The platform runs as uid 1000 and reads config.json, the service account key and the LDAP certificate (for **Check connections**). radius.env is read by Docker as root only.

```bash
cd /etc/wifi-portal
sudo chown root:1000 config.json service-account.json google-ldap google-ldap/*
sudo chmod 640 config.json service-account.json google-ldap/*
sudo chmod 750 google-ldap
sudo chown root:root radius.env && sudo chmod 600 radius.env
```

- **Shared token:** generate one with `openssl rand -hex 32` and put it in both `radius.apiToken` (config.json) and `PLATFORM_TOKEN` (radius.env).
- **RADIUS secret:** generate a second one the same way for `RADIUS_SECRET`, and set the same secret on the vSZ RADIUS service.
- **VSZ_ADDRESS:** set it to the school's public IP.
- **Guest settings:** first run `docker compose run --rm wifi-portal node scripts/vsz-fingerprint.js /etc/wifi-portal/config.json` for `dpsk.tlsFingerprint`, then `… scripts/vsz-wlans.js …` for `dpsk.zoneId` and `dpsk.wlanId` (the WLAN list won't connect while the fingerprint is still the placeholder). The platform won't start without the fingerprint, because the vSZ API password crosses the internet. Compare it with the certificate shown in the vSZ web console (padlock → certificate → SHA-256) before trusting it.

Then start everything:

```bash
docker compose up -d --build
docker compose logs -f freeradius wifi-portal
```

Caddy gets both certificates within a minute. FreeRADIUS restarts once a day, which also picks up renewed certificates. On the very first start FreeRADIUS waits for Caddy's certificate before it starts. To see every login in detail while setting up, set `RADIUS_DEBUG=1` in radius.env and run `docker compose up -d freeradius`.

**Check it works**, before touching the vSZ:

1. **Connections:** in the dashboard, **Settings → Check connections**, or on the server:
   `docker compose exec wifi-portal node scripts/check-connections.js /etc/wifi-portal/config.json`.
   It tries the Google directory, Google Secure LDAP with the client certificate and access credentials, the vSZ API, the vSZ portal interface (NBI), and sends a test alert email (`--no-email` skips it), and says what's wrong for any that fail.
2. **A real sign-in:** join Nexus with a phone and sign in. **Activity** shows it, and **People** shows the device and network.

**Monitoring:** `docker compose ps` shows each container's health (the platform answers `/healthz`; FreeRADIUS answers a local Status-Server check). Point an uptime monitor (for example Uptime Kuma, or your RMM) at `https://wifi.phahs.org.za/healthz`. Docker's logs are capped at 5 × 20 MB per container, and `wifi.jsonl` rotates at 50 MB, keeping 5 old copies.

### 5. Connecting devices

Nothing to set up on any device. Join the network for your group, sign in on the page that opens, done. The dashboard's **Settings → Connection guide** prints a one-page guide for staff and learners.

If the page doesn't open by itself, open any `http://` website (for example `http://example.com`). A phone's "private WiFi address" stays the same per network, so being remembered works; a device that changes it (for example iOS set to **Rotating**) signs in again when it does.

## Rules

Rules are checked from top to bottom, and the first match wins. A rule matches on `orgUnit` (that OU and everything under it) and/or `email` (a regex), then either lets people on with a `vlanId` or turns them away (`deny`, with a `message`). Edit them in the dashboard's **Rules** page; the example config starts with:

```json
"policy": {
  "rules": [
    { "name": "Shared accounts", "email": "^(exam|shared)\\.", "deny": true, "message": "Shared accounts can't use the school WiFi." },
    { "name": "Staff",    "orgUnit": "/Staff",    "vlanId": 20 },
    { "name": "Students", "orgUnit": "/Students", "vlanId": 30 }
  ],
  "default": null
}
```

`"default": null` turns away anyone no rule matched. Personal Gmail and other domains are always turned away. So are suspended, archived and deleted Google accounts, and anyone blocked in the dashboard.

## Admin dashboard

`https://wifi.phahs.org.za/admin`, signed in with Google. Only `admin.emails` get in.

| Page | What it's for |
|---|---|
| **Overview** | People and devices logged in today, people turned away, guest SSID keys, problems. Health shows whether logins are arriving from FreeRADIUS, the Google directory, the vSZ API, backups and alerts. Also lists the latest logins. |
| **Activity** | Every login (once per device per day), every refusal with its reason (wrong password, blocked, suspended, rule, wrong domain), key changes and admin actions. |
| **People** | Everyone who has logged in or been turned away, with their devices, VLAN, **data used per day for 30 days**, sessions and history. **Block** turns someone away at their next login. |
| **Usage** | Data downloaded and uploaded today, over 7 days or over 30 days: the top 50 people, totals per VLAN, and everyone online now with their device, IP and data this session. CSV export. |
| **Guests** | Make a visitor key on the Guest network for 1–`maxGuestDays` days and print or show the slip. **Reset** frees a key for another phone; **End** stops it early. |
| **Rules** | Allowed domains, plus rules from org unit to VLAN. |
| **Settings** | Name, the **daily usage alert** level, record retention, platform facts, and tools: check connections, the printable **connection guide**, back up now, adopt keys from the vSZ, export usage, logins and keys as CSV. |

Everything is kept in `/var/lib/wifi-portal/wifi-portal.db`, with a copy every night in `backups/`; the last 14 are kept. With `backup.drive` set, each copy also goes to Google Drive. To restore one: stop the platform, move `wifi-portal.db` and its `-wal` and `-shm` files aside, copy the backup in as `wifi-portal.db` (gunzip a Drive copy first) owned by uid 1000, start it again, then use **Settings → Adopt keys** for guest keys made since.

**Connection guide:** **Settings → Connection guide** opens a one-page guide for staff and learners, filled in from the config: how to connect each kind of device, what to do if it fails, and what the school records about WiFi use, for POPIA. Print it, or save it as PDF for the website or newsletter. Check the privacy wording against the school's ICT policy first.

## Usage

- **How the figures work:** each session's counters arrive with the vSZ's interim updates. The platform adds the growth since the last report to that day's total, per person and device. Sessions over 4 GB are counted correctly (gigawords). If the vSZ restarts, its open sessions are closed.
- **Lag:** figures lag by up to one interim interval. "Online now" means a session reported within the last `radius.accountingStaleMinutes` (30).
- **The alert:** set a **daily usage alert** under Settings (or `usage.alertGb` in config) and IT gets an email, plus an entry in Activity → High usage, the first time someone passes it each day.
- **Privacy:** usage is personal information under POPIA. It follows the same `retentionDays` as everything else and is visible only to dashboard admins.

## If something is down

- **The platform** (`wifi-portal`) down: FreeRADIUS follows `FALLBACK_VLAN`. Empty means no new logins; a VLAN number lets anyone with a correct Google password on to that VLAN, with blocks and rules skipped until the platform is back. Devices that are already connected stay connected either way.
- **The platform answers but refuses FreeRADIUS** (the token in radius.env and config.json differ, or a wrong `PLATFORM_URL`): every login is refused, never let through without the rules. Activity stays empty and Overview → Health says FreeRADIUS hasn't called.
- **Google** down or over quota: no new logins. Connected devices stay on until their session ends. You get an alert email.
- **The vSZ API** down: only Guest key changes wait.

## Testing

- `npm test`: unit tests for the VLAN decision API, usage accounting, rules, dashboard, guest keys, backups, alerts and vSZ certificate pinning.
- `npm run test:radius` (needs Docker): real WPA2-Enterprise logins with `eapol_test` against FreeRADIUS built from `deploy/freeradius`. An OpenLDAP server stands in for Google. It checks:
  - staff and learners land on their VLANs;
  - wrong passwords, blocked people, rule-denied and unknown accounts are refused;
  - the dashboard records each outcome;
  - the password never reaches the platform;
  - the Access-Accept carries the real login name, and accounting sent to port 1813 is recorded as usage;
  - the Docker health check answers;
  - a token mismatch between FreeRADIUS and the platform refuses logins.

## Pilot

Run Nexus next to the current network for one or two weeks with IT and a few teachers before telling everyone. Tick off:

| # | Check | How |
|---|---|---|
| 1 | Every connection works | **Settings → Check connections**: all green, and the test email arrived. |
| 2 | Google checks passwords | Sign in on the page with a staff account on Nexus Staff and a learner account on Nexus: both connected. Then a wrong password (refused), and a learner on Nexus Staff (told to use Nexus). |
| 3 | The vSZ applies the VLAN | A staff phone and a learner phone on Nexus get addresses from their own VLANs. **People** shows the VLAN each login was given. |
| 4 | Usage arrives | After 10–20 minutes online, the phone shows under **Usage → Online now** with growing figures. |
| 5 | Every kind of device | iPhone with the profile, a Mac, Android with the Domain set, a Windows laptop with the profile, a school Chromebook, and a personal Chromebook. |
| 6 | Turning people away | Block a test account: its next login is refused, with the reason under **Activity**. Unblock it. Do the same with a suspended test account in Google. |
| 7 | Roaming | Walk a phone across the school on a call or video: it shouldn't drop, and Activity shouldn't fill with logins (fast roaming works). |
| 8 | Guests | Make a guest key, print the slip, join the Guest network with it, then end it: the phone can't join again (note whether the vSZ also drops it at once). |
| 9 | Fallback | Decide `FALLBACK_VLAN`. Stop the platform (`docker compose stop wifi-portal`) and see that new logins do what you decided. Start it again. |
| 10 | Backups | **Settings → Back up now**; with Drive set up, the copy appears in the Shared Drive. |
| 11 | A busy morning | During the first full morning, watch **Overview** for `directory_error` and slow logins. |

Then hand out the connection guide, send the Apple and Windows profiles, and push the network to managed Chromebooks.

## Things to check when going live

- **Google Secure LDAP:** the client is **On** and has both permissions. The first login of the day may take a second or two.
- **Dynamic VLAN on Nexus:** people on different rules really end up on different VLANs. The **Overview** and **People** pages show the VLAN each login was given.
- **Certificate on Android:** set **Domain** to exactly `radius.phahs.org.za`. Old Android versions without that field can't check the server; send those devices to the Guest network rather than turning validation off.
- **Quotas:** watch for `directory_error` alerts in the first busy week, and keep fast roaming on.
- **RADIUS across the internet:** the vSZ reaches FreeRADIUS over the internet, protected by the shared secret and the school-IP firewall rule. Use a long random secret (`openssl rand -hex 32`). If the vSZ and the server can share a VPN (WireGuard or IPsec), sending RADIUS through it is better still.
- **Dashboard access:** set `admin.allowFrom` to the school's public IP (and yours) if admins only use it from known places.
- **vSZ API account:** give the platform's vSZ account the smallest role that can manage DPSKs on the Guest WLAN.
