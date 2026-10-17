import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "../api/client";
import { MAX_BACKOFF_MS, nextDelay, usePolling } from "./usePolling";

function Probe({ load, interval }: { load: () => Promise<number>; interval: number }) {
  const { data, error, refresh } = usePolling(load, interval);
  return (
    <div>
      <span data-testid="data">{data ?? "none"}</span>
      <span data-testid="error">{error ? "error" : "ok"}</span>
      <button onClick={refresh}>refresh</button>
    </div>
  );
}

describe("nextDelay", () => {
  it("backs off exponentially to 120 s and honours Retry-After", () => {
    expect(nextDelay(15_000, 0, null)).toBe(15_000);
    expect(nextDelay(15_000, 1, new Error())).toBe(30_000);
    expect(nextDelay(15_000, 5, new Error())).toBe(MAX_BACKOFF_MS);
    expect(nextDelay(15_000, 1, new ApiError(429, "RATE_LIMITED", undefined, 90))).toBe(90_000);
  });
});

describe("usePolling", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("polls on the interval, pauses while hidden and backs off on errors", async () => {
    let n = 0;
    const load = vi.fn(async () => {
      n += 1;
      if (n === 3) throw new Error("boom");
      return n;
    });
    render(<Probe load={load} interval={1000} />);
    await act(async () => vi.advanceTimersByTimeAsync(0));
    expect(screen.getByTestId("data").textContent).toBe("1");
    await act(async () => vi.advanceTimersByTimeAsync(1000));
    expect(screen.getByTestId("data").textContent).toBe("2");
    await act(async () => vi.advanceTimersByTimeAsync(1000));
    expect(screen.getByTestId("error").textContent).toBe("error");
    await act(async () => vi.advanceTimersByTimeAsync(1000));
    expect(load).toHaveBeenCalledTimes(3); // backoff: 2 s after the first failure
    await act(async () => vi.advanceTimersByTimeAsync(1000));
    expect(screen.getByTestId("data").textContent).toBe("4");

    Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
    await act(async () => vi.advanceTimersByTimeAsync(5000));
    expect(load).toHaveBeenCalledTimes(4);
    Object.defineProperty(document, "hidden", { configurable: true, get: () => false });
    await act(async () => {
      document.dispatchEvent(new Event("visibilitychange"));
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(load).toHaveBeenCalledTimes(5);
    await act(async () => {
      screen.getByText("refresh").click();
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(load).toHaveBeenCalledTimes(6);
  });
});
