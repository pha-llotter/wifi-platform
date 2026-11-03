// Emails IT when something needs attention. Each kind of alert goes out at most once
// an hour so an outage doesn't flood anyone's inbox.
export function createAlerts({ mailer = null, to = [], publicUrl, log, minIntervalMs = 3600_000 }) {
  const lastSent = new Map();
  const status = { enabled: Boolean(mailer && to.length), to, lastSent: null, lastError: null };

  async function alert(kind, subject, text) {
    if (!status.enabled) return false;
    const now = Date.now();
    if (lastSent.get(kind) > now - minIntervalMs) return false;
    lastSent.set(kind, now);
    try {
      await mailer.send({ to, subject: `[WiFi] ${subject}`, text: `${text}\n\nDashboard: ${publicUrl}/admin` });
      status.lastSent = now;
      log('alert_sent', { subject });
      return true;
    } catch (err) {
      status.lastError = err.message;
      log('alert_error', { subject, error: err.message });
      return false;
    }
  }

  // Decides from each logged event whether IT should hear about it.
  function onEvent(event, data) {
    if (event === 'vsz_error' || (event === 'key_sync_error' && !data.email)) {
      alert('vsz', "The vSZ API isn't working", `The platform couldn't talk to the vSZ, so WiFi keys can't be issued or removed.\n\n${data.error}`);
    } else if (event === 'key_sync_error') {
      alert('sync', 'The key sync hit a problem', `${data.email ?? ''}: ${data.error}`);
    } else if (event === 'directory_error') {
      alert('directory', "The Google directory isn't answering", `New logins to the school WiFi use the fallback VLAN (or fail) until it answers.\n\n${data.error}`);
    } else if (event === 'google_error') {
      alert('google', "Google sign-in isn't working", data.error);
    } else if (event === 'backup_error') {
      alert('backup', 'The nightly backup failed', `${data.error}\n\nThe database itself is fine; only the copy failed.`);
    } else if (event === 'usage_high') {
      alert(`usage:${data.email}`, `${data.email} used ${data.gb} GB today`, `${data.email} has used ${data.gb} GB on the WiFi today, over the ${data.limitGb} GB alert level. Their devices and sessions are on their page in the dashboard.`);
    } else if (event === 'key_sync' && data.revoked >= 20) {
      alert('mass-revoke', `${data.revoked} WiFi keys were removed in one sync`, `The sync removed ${data.revoked} keys (people suspended, blocked or no longer allowed by a rule). If that's unexpected, check the rules and the Activity page.`);
    }
  }

  return { alert, onEvent, status };
}
