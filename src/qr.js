// QR codes as inline SVG, drawn from the module grid of the vendored
// qrcode-generator 1.4.4 (MIT, Kazuhiko Arase).
import { createRequire } from 'node:module';

const qrcode = createRequire(import.meta.url)('./vendor/qrcode.cjs');

export function qrSvg(text, { label = 'QR code' } = {}) {
  const qr = qrcode(0, 'M');
  qr.addData(text, 'Byte');
  qr.make();
  const n = qr.getModuleCount();
  const margin = 4;
  const size = n + margin * 2;
  let d = '';
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) if (qr.isDark(r, c)) d += `M${c + margin} ${r + margin}h1v1h-1z`;
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" role="img" aria-label="${label}"><rect width="${size}" height="${size}" fill="#fff"/><path d="${d}" fill="#000"/></svg>`;
}

// The format phone cameras understand for "join this WiFi".
export function wifiQrText({ ssid, passphrase }) {
  const esc = (s) => String(s).replace(/([\\;,:"])/g, '\\$1');
  return `WIFI:T:WPA;S:${esc(ssid)};P:${esc(passphrase)};;`;
}
