import type { Principal } from "../auth/principal";

declare global {
  namespace Express {
    interface Request {
      requestId: string;
      principal?: Principal;
      source: { ip: string | null; trusted: boolean };
    }
  }
}

export {};
