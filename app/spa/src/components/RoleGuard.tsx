import type { ReactNode } from "react";
import type { Permission } from "../api/types";
import { useSession } from "../auth/session";

/** UX only: hides pages the user cannot use. The server enforces every permission. */
export function RoleGuard({ need, children }: { need: Permission; children: ReactNode }) {
  const { can } = useSession();
  if (!can(need)) {
    return (
      <div role="alert" className="rounded border border-slate-300 bg-white p-4 text-sm">
        You do not have access to this page.
      </div>
    );
  }
  return <>{children}</>;
}
