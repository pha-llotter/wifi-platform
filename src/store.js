// In-memory map whose entries expire. Everything the portal keeps is short-lived
// (sign-in sessions, one-time passwords), so a restart only interrupts sign-ins in flight.
// `max` caps the size: past it the oldest entries are dropped, so a flood of requests
// can't exhaust memory.
export class TtlMap {
  #entries = new Map();

  constructor({ max = Infinity } = {}) {
    this.max = max;
    this.timer = setInterval(() => this.sweep(), 30_000);
    this.timer.unref();
  }

  set(key, value, ttlMs) {
    this.#entries.delete(key);
    this.#entries.set(key, { value, expires: Date.now() + ttlMs });
    while (this.#entries.size > this.max) this.#entries.delete(this.#entries.keys().next().value);
    return value;
  }

  get(key) {
    const e = this.#entries.get(key);
    if (!e) return undefined;
    if (e.expires < Date.now()) {
      this.#entries.delete(key);
      return undefined;
    }
    return e.value;
  }

  delete(key) {
    this.#entries.delete(key);
  }

  clear() {
    this.#entries.clear();
  }

  get size() {
    return this.#entries.size;
  }

  sweep() {
    const now = Date.now();
    for (const [k, e] of this.#entries) if (e.expires < now) this.#entries.delete(k);
  }

  close() {
    clearInterval(this.timer);
  }
}
