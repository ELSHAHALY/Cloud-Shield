// DynamoDB conditional-failure classification (audit E4). Only a real
// ConditionalCheckFailed becomes a business error (404 / 409 / 412); a
// TransactionConflict is a retryable 409; throttling, validation and every
// other cancellation reason stay internal errors (500), never a
// misleading "already exists" or "someone else edited this".
import { AppError } from "./errors";

interface CancelledError {
  name?: string;
  CancellationReasons?: { Code?: string }[];
}

export function isConditionFailure(err: unknown): boolean {
  const e = err as CancelledError | null;
  if (e?.name === "ConditionalCheckFailedException") return true;
  if (e?.name !== "TransactionCanceledException" || !Array.isArray(e.CancellationReasons)) return false;
  const codes = e.CancellationReasons.map((r) => r?.Code ?? "None");
  return codes.includes("ConditionalCheckFailed") && codes.every((c) => c === "ConditionalCheckFailed" || c === "None");
}

/** Rethrows anything that is not a condition failure; maps TransactionConflict to a retryable 409. */
export function rethrowUnlessConditionFailure(err: unknown): void {
  if (isConditionFailure(err)) return;
  const e = err as CancelledError | null;
  if (e?.name === "TransactionCanceledException" && e.CancellationReasons?.some((r) => r?.Code === "TransactionConflict")) {
    throw new AppError("CONFLICT", "concurrent update: retry");
  }
  throw err;
}
