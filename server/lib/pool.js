/* ============================================================================
   Bounded concurrency with cooperative pause and cancel.
   ========================================================================= */
'use strict';

class Control {
  constructor() {
    this.cancelled = false;
    this.paused = false;
    this._waiters = [];
  }

  cancel() { this.cancelled = true; this.resume(); }
  pause() { this.paused = true; }

  resume() {
    this.paused = false;
    const waiting = this._waiters;
    this._waiters = [];
    waiting.forEach((fn) => fn());
  }

  /** Await between work items. Throws CANCELLED so callers unwind cleanly. */
  async checkpoint() {
    while (this.paused && !this.cancelled) {
      await new Promise((resolve) => this._waiters.push(resolve));
    }
    if (this.cancelled) {
      const e = new Error('Assessment cancelled by the operator.');
      e.code = 'CANCELLED';
      throw e;
    }
  }
}

/**
 * Run `worker` over `items` with at most `limit` in flight.
 *
 * Results keep input order. A worker that throws yields null in that slot
 * rather than tearing down the whole sweep — one unreachable host must not
 * end an assessment. Cancellation is the exception: it propagates.
 */
async function pool(items, limit, worker, control) {
  const out = new Array(items.length);
  const width = Math.max(1, Math.min(limit, items.length));
  let cursor = 0;
  let cancelled = null;

  const runner = async () => {
    for (;;) {
      const index = cursor++;
      if (index >= items.length) return;
      if (cancelled) return;
      try {
        if (control) await control.checkpoint();
        out[index] = await worker(items[index], index);
      } catch (err) {
        if (err && err.code === 'CANCELLED') { cancelled = err; return; }
        out[index] = null;
      }
    }
  };

  await Promise.all(new Array(width).fill(0).map(runner));
  if (cancelled) throw cancelled;
  return out;
}

/** Resolve to null after `ms` rather than hanging a sweep on one slow host. */
function withTimeout(promise, ms, fallback) {
  let timer = null;
  const guard = new Promise((resolve) => {
    timer = setTimeout(() => resolve(fallback === undefined ? null : fallback), ms);
  });
  return Promise.race([promise, guard]).then((value) => {
    if (timer) clearTimeout(timer);
    return value;
  });
}

module.exports = { Control, pool, withTimeout };
