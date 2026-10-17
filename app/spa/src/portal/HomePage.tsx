import { useEffect, useState } from "react";
import { Link } from "react-router";
import type { AgreementStatus } from "../api/types";
import { useSession } from "../auth/session";
import { Card } from "../components/ui";

export function HomePage() {
  const { me, api, can } = useSession();
  const [status, setStatus] = useState<AgreementStatus | null>(null);

  useEffect(() => {
    if (!can("agreement:read")) return;
    api.get<AgreementStatus>("/agreements/status").then(setStatus).catch(() => setStatus(null));
  }, [api, can]);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Welcome</h1>
      {status && !status.complete && (
        <p role="status" className="rounded border border-amber-300 bg-amber-50 p-3 text-sm">
          Your tenant has not accepted the required agreements yet: document uploads and changes are blocked.{" "}
          <Link to="/onboarding" className="underline">
            {can("agreement:accept") ? "Review and accept them" : "See status"}
          </Link>
          .
        </p>
      )}
      <Card title="Your access">
        <dl className="grid grid-cols-3 gap-1 text-sm">
          <dt className="text-slate-600">Tenant</dt>
          <dd className="col-span-2 font-mono">{me.tenantId}</dd>
          <dt className="text-slate-600">Groups</dt>
          <dd className="col-span-2">{me.groups.join(", ") || "none"}</dd>
          <dt className="text-slate-600">Permissions</dt>
          <dd className="col-span-2 font-mono text-xs">{me.permissions.join(" ") || "none"}</dd>
        </dl>
      </Card>
    </div>
  );
}
