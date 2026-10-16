// Shared refusal checks: these tools must never run against real AWS or
// outside local mode (plan D22).
export const LOCAL_HOSTS: ReadonlySet<string> = new Set(["moto", "localhost", "127.0.0.1", "::1"]);

export function isLocalEndpoint(value: string | undefined): boolean {
  if (!value) return false;
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;
    if (url.username || url.password) return false;
    return LOCAL_HOSTS.has(url.hostname.replace(/^\[|\]$/g, ""));
  } catch {
    return false;
  }
}

export function requireLocalMode(env: NodeJS.ProcessEnv): void {
  if (env.CLOUDSHIELD_ENV !== "local") throw new Error("refusing to run: CLOUDSHIELD_ENV must be local");
}
