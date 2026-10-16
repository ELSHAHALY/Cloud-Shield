import type { NextFunction, Request, Response } from "express";
import { AppError } from "../lib/errors";
import type { Permission } from "./principal";

/** Route guard (RBAC). ABAC (owner, tenant) is enforced inside the services. */
export function requirePermission(permission: Permission) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!req.principal?.permissions.has(permission)) {
      next(new AppError("FORBIDDEN"));
      return;
    }
    next();
  };
}
