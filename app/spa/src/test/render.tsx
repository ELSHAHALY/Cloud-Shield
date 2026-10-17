import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter, Route, Routes } from "react-router";
import { vi } from "vitest";
import type { ApiClient } from "../api/client";
import type { Me, Permission } from "../api/types";
import type { AuthBackend } from "../auth/backend";
import { makeCan, SessionContext } from "../auth/session";

export const PERMS: Record<string, Permission[]> = {
  admin: ["doc:read", "doc:write", "doc:delete", "audit:read", "agreement:read", "agreement:accept", "grc:read", "grc:assess", "grc:profile:write"],
  member: ["doc:read", "doc:write", "doc:delete", "agreement:read", "grc:read"],
  auditor: ["doc:read", "audit:read", "agreement:read", "grc:read", "grc:assess"],
  "secops-analyst": ["agreement:read", "grc:read", "soc:read", "soc:evidence", "posture:read"],
};

export function meFor(group: keyof typeof PERMS, sub = `sub-${group}`): Me {
  return { sub, email: `${group}@example.test`, tenantId: "t-acme-01", groups: [group as Me["groups"][number]], permissions: PERMS[group]! };
}

type Handler = (method: string, path: string, opts?: unknown) => unknown;

/** A fake ApiClient routed by "METHOD /path" prefix; unknown routes reject. */
export function fakeApi(routes: Record<string, unknown | ((path: string, body?: unknown) => unknown)>): ApiClient & { calls: [string, string, unknown?][] } {
  const calls: [string, string, unknown?][] = [];
  const handle: Handler = (method, path, opts) => {
    calls.push([method, path, opts]);
    const key = Object.keys(routes)
      .filter((k) => {
        const [m, p] = k.split(" ");
        return m === method && path.startsWith(p!);
      })
      .sort((a, b) => b.length - a.length)[0];
    if (!key) return Promise.reject(new Error(`unmocked ${method} ${path}`));
    const v = routes[key];
    try {
      const out = typeof v === "function" ? (v as (p: string, b?: unknown) => unknown)(path, opts) : v;
      return out instanceof Promise ? out : Promise.resolve(out);
    } catch (e) {
      return Promise.reject(e);
    }
  };
  return {
    calls,
    request: vi.fn((method: string, path: string, opts?: unknown) => handle(method, path, opts)) as ApiClient["request"],
    get: vi.fn((path: string) => handle("GET", path)) as ApiClient["get"],
    post: vi.fn((path: string, body: unknown) => handle("POST", path, body)) as ApiClient["post"],
    put: vi.fn((path: string, body: unknown) => handle("PUT", path, body)) as ApiClient["put"],
    patch: vi.fn((path: string, body: unknown, headers?: unknown) => handle("PATCH", path, { body, headers })) as ApiClient["patch"],
    del: vi.fn((path: string) => handle("DELETE", path)) as ApiClient["del"],
  };
}

export const fakeBackend: AuthBackend = {
  mode: "local",
  getIdToken: async () => "t",
  signOut: async () => undefined,
  LoginForm: () => null,
};

export function renderWithSession(ui: ReactElement, { me = meFor("admin"), api = fakeApi({}), path = "/", route = "*" }: { me?: Me; api?: ApiClient; path?: string; route?: string } = {}) {
  const signOut = vi.fn(async () => undefined);
  const result = render(
    <MemoryRouter initialEntries={[path]}>
      <SessionContext.Provider value={{ me, api, backend: fakeBackend, can: makeCan(me), signOut }}>
        <Routes>
          <Route path={route} element={ui} />
        </Routes>
      </SessionContext.Provider>
    </MemoryRouter>,
  );
  return { ...result, api, signOut };
}
