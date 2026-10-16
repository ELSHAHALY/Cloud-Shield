// "Live" means polling (plan D19): every `intervalMs` while the tab is
// visible, doubling up to 120 s on errors and honouring Retry-After.
import { useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";

export const MAX_BACKOFF_MS = 120_000;

export function nextDelay(intervalMs: number, failures: number, err: unknown): number {
  if (failures === 0) return intervalMs;
  const backoff = Math.min(MAX_BACKOFF_MS, intervalMs * 2 ** failures);
  const retryAfter = err instanceof ApiError && err.retryAfterSeconds ? err.retryAfterSeconds * 1000 : 0;
  return Math.max(backoff, retryAfter);
}

interface PollState<T> {
  data: T | null;
  error: unknown;
  updatedAt: Date | null;
}

export function usePolling<T>(load: () => Promise<T>, intervalMs = 15_000) {
  const [state, setState] = useState<PollState<T>>({ data: null, error: null, updatedAt: null });
  const [nonce, setNonce] = useState(0);
  const loadRef = useRef(load);

  useEffect(() => {
    loadRef.current = load;
  });

  useEffect(() => {
    let alive = true;
    let failures = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;

    function schedule(ms: number) {
      clearTimeout(timer);
      timer = setTimeout(run, ms);
    }

    function run() {
      if (document.hidden) {
        schedule(intervalMs);
        return;
      }
      loadRef
        .current()
        .then((data) => {
          if (!alive) return;
          failures = 0;
          setState({ data, error: null, updatedAt: new Date() });
          schedule(intervalMs);
        })
        .catch((error: unknown) => {
          if (!alive) return;
          failures += 1;
          setState((s) => ({ ...s, error }));
          schedule(nextDelay(intervalMs, failures, error));
        });
    }

    function onVisible() {
      if (!document.hidden) schedule(0);
    }

    schedule(0);
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      alive = false;
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [intervalMs, nonce]);

  return { ...state, refresh: () => setNonce((n) => n + 1) };
}
