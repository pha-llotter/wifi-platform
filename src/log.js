import fs from 'node:fs';
import path from 'node:path';

// One JSON object per line, to stdout and (optionally) an append-only file that
// doubles as the record of who signed in on which device. The file is rotated when it
// passes maxBytes, keeping `keep` old copies (wifi.jsonl.1 is the newest). Writes are
// synchronous: a few lines a second at most, and nothing is lost on a crash.
export function createLogger(file, { maxBytes = 50 * 1024 ** 2, keep = 5 } = {}) {
  let fd = null;
  let size = 0;
  const open = () => {
    fd = fs.openSync(file, 'a');
    size = fs.fstatSync(fd).size;
  };
  const rotate = () => {
    fs.closeSync(fd);
    for (let i = keep - 1; i >= 1; i--) {
      try {
        fs.renameSync(`${file}.${i}`, `${file}.${i + 1}`);
      } catch {}
    }
    fs.renameSync(file, `${file}.1`);
    open();
  };
  if (file) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    open();
  }
  const log = (event, data = {}) => {
    const line = `${JSON.stringify({ time: new Date().toISOString(), event, ...data })}\n`;
    process.stdout.write(line);
    if (fd === null) return;
    try {
      const bytes = Buffer.byteLength(line);
      if (size > 0 && size + bytes > maxBytes) rotate();
      fs.writeSync(fd, line);
      size += bytes;
    } catch (err) {
      console.error(`log file: ${err.message}`);
    }
  };
  log.close = () => {
    if (fd !== null) fs.closeSync(fd);
    fd = null;
  };
  return log;
}
