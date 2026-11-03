// The platform's HTTP entry point. There is no public website: people join the school
// WiFi with their Google login and FreeRADIUS checks it. This serves
//   /admin/*   the admin dashboard
//   /radius/*  the API FreeRADIUS calls during logins (local only, see radius-api.js)
//   /healthz   for uptime checks
// and sends everything else to the dashboard.
export function createApp({ admin, radiusApi, log }) {
  async function handle(req, res) {
    const url = new URL(req.url, 'http://portal');
    try {
      if (url.pathname.startsWith('/radius/')) return await radiusApi.handle(req, res, url);
      if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) return await admin.handle(req, res, url);
      if (url.pathname === '/healthz') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end('ok');
      }
      res.writeHead(302, { Location: '/admin', 'Cache-Control': 'no-store' });
      res.end();
    } catch (err) {
      log('http_error', { path: url.pathname, error: err.message });
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Something went wrong.');
      }
    }
  }
  return { handle };
}
