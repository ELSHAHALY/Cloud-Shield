// The header's live indicator reflects a page that is really polling (today
// only the SOC dashboard). Nothing is shown when no page reports in.
import { createContext, useContext, useEffect } from "react";

export interface LiveState {
  label: string;
  intervalSeconds: number;
  updatedAt: Date | null;
  failing: boolean;
}

export const LiveContext = createContext<(s: LiveState | null) => void>(() => undefined);

/** Reports this page's polling state to the shell for as long as it is mounted. */
export function useReportLive(state: LiveState | null): void {
  const report = useContext(LiveContext);
  const key = state ? `${state.label}|${state.intervalSeconds}|${state.updatedAt?.getTime() ?? ""}|${state.failing}` : "";
  useEffect(() => {
    report(state);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `key` captures every field of `state`
  }, [report, key]);
  useEffect(() => () => report(null), [report]);
}
