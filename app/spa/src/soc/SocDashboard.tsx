import { useCallback } from "react";
import type { Posture, SocOverview } from "../api/types";
import { useSession } from "../auth/session";
import { Card, ErrorBox, Loading } from "../components/ui";
import { usePolling } from "../hooks/usePolling";
import { IncidentsTable } from "./IncidentsTable";
import { MitreBreakdown } from "./MitreBreakdown";
import { MttcMeter } from "./MttcMeter";
import { PostureBanner } from "./PostureBanner";

export function SocDashboard() {
  const { api } = useSession();
  const overview = usePolling(useCallback(() => api.get<SocOverview>("/soc/overview"), [api]), 15_000);
  const posture = usePolling(useCallback(() => api.get<Posture>("/soc/posture"), [api]), 60_000);
  const o = overview.data;
  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">SecOps SOC</h1>
        <p className="text-xs text-slate-600" aria-live="polite">
          {overview.updatedAt ? `Updated ${overview.updatedAt.toLocaleTimeString()} · refreshes every 15 s while this tab is visible` : ""}
        </p>
      </div>
      <ErrorBox error={overview.error} />
      {posture.data && <PostureBanner posture={posture.data} />}
      {!o && !overview.error && <Loading />}
      {o && (
        <>
          <div className="grid gap-4 md:grid-cols-2">
            <Card title="Mean time to contain (24 h)">
              <MttcMeter mttc={o.metrics.mttc} />
            </Card>
            <Card title="ATT&CK tactics (24 h)">
              <MitreBreakdown byTactic={o.metrics.byTactic} />
            </Card>
          </div>
          <Card title="Latest incidents">
            <IncidentsTable incidents={o.incidents} />
          </Card>
        </>
      )}
    </div>
  );
}
