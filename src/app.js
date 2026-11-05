// The platform's HTTP entry point:
//   /, /connect, /portal/*  the WiFi sign-in page the vSZ sends new devices to (portal.js)
//   /admin/*                the admin dashboard
//   /radius/*               the API FreeRADIUS calls during logins (local only, see radius-api.js)
//   /healthz                for uptime checks
export function createApp({ admin, radiusApi, portal = null, log }) {
  async function handle(req, res) {
    const url = new URL(req.url, 'http://portal');
    try {
      if (url.pathname.startsWith('/radius/')) return await radiusApi.handle(req, res, url);
      if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) return await admin.handle(req, res, url);
      if (url.pathname === '/healthz') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end('ok');
      }
      if (portal && (await portal.handle(req, res, url)) !== null) return;
      res.writeHead(302, { Location: portal ? '/' : '/admin', 'Cache-Control': 'no-store' });
      res.end();
    } catch (err) {
      log('http_error', { path: url.pathname, error: err.message });
      if (!res.headersSent) {
        res.writeHead(err.status ?? 500, { 'Content-Type': 'text/plain' });
        res.end('Something went wrong.');
      }
    }
  }
  return { handle };
}
