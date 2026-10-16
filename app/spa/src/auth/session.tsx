import { createContext, useContext } from "react";
import type { ApiClient } from "../api/client";
import type { Me, Permission } from "../api/types";
import type { AuthBackend } from "./backend";

export interface Session {
  me: Me;
  api: ApiClient;
  backend: AuthBackend;
  can(p: Permission): boolean;
  signOut(): Promise<void>;
}

export const SessionContext = createContext<Session | null>(null);

export function useSession(): Session {
  const s = useContext(SessionContext);
  if (!s) throw new Error("useSession outside SessionContext");
  return s;
}

export function makeCan(me: Me) {
  const set = new Set(me.permissions);
  return (p: Permission) => set.has(p);
}
