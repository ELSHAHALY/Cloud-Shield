import type { ReactNode } from "react";
import type { Permission } from "../api/types";
import { useSession } from "../auth/session";
import { Icon } from "./ui";

/** UX only: hides pages the user cannot use. The server enforces every permission. */
export function RoleGuard({ need, children }: { need: Permission; children: ReactNode }) {
  const { can } = useSession();
  if (!can(need)) {
    return (
      <div role="alert" className="glass flex items-center gap-3 p-5 text-sm text-slate-300">
        <Icon name="lock" className="size-5 text-amber-300" />
        You do not have access to this page.
      </div>
    );
  }
  return <>{children}</>;
}
