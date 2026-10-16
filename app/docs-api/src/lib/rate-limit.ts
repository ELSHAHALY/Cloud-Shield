// Fixed-window in-memory limiter. Per task, so with N tasks the effective
// limit is N×; WAF and API Gateway throttling stay the real limits (plan §4.1).
// Bounded: at most `maxKeys` keys are tracked; past that, expired windows are
// swept and, if still full, the request is counted against a shared overflow
// key so memory cannot grow without limit.
export class RateLimiter {
  private readonly hits = new Map<string, { windowStart: number; count: number }>();

  constructor(
    readonly limit: number,
    readonly windowMs: number,
    private readonly maxKeys = 10_000,
    private readonly now: () => number = Date.now,
  ) {}

  /** Returns 0 when allowed, else the seconds until the window resets. */
  take(key: string): number {
    const t = this.now();
    let k = key;
    if (!this.hits.has(k) && this.hits.size >= this.maxKeys) {
      this.sweep(t);
      if (this.hits.size >= this.maxKeys) k = "\u0000overflow";
    }
    const entry = this.hits.get(k);
    if (!entry || t - entry.windowStart >= this.windowMs) {
      this.hits.set(k, { windowStart: t, count: 1 });
      return 0;
    }
    entry.count += 1;
    if (entry.count <= this.limit) return 0;
    return Math.max(1, Math.ceil((entry.windowStart + this.windowMs - t) / 1000));
  }

  /** Seconds until reset if `key` is already at its limit, else 0. Does not count. */
  blocked(key: string): number {
    const t = this.now();
    const entry = this.hits.get(key);
    if (!entry || t - entry.windowStart >= this.windowMs || entry.count < this.limit) return 0;
    return Math.max(1, Math.ceil((entry.windowStart + this.windowMs - t) / 1000));
  }

  private sweep(t: number): void {
    for (const [k, v] of this.hits) {
      if (t - v.windowStart >= this.windowMs) this.hits.delete(k);
    }
  }

  get size(): number {
    return this.hits.size;
  }
}
