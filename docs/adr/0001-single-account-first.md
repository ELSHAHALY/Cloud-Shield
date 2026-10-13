# ADR-0001 — Build single-account first, keep the multi-account design

- **Status:** Accepted (8 Oct 2026)
- **Deciders:** S1, S2, S3
- **Relates to:** Plan §4.2 (account structure), gap **G2**, risk **R5**

## Context

The architecture (plan §4.2) puts the security tooling in a separate Security account so that a fully compromised workload account cannot erase the evidence or switch off detection. That isolation is the strongest argument in the design.

But:

1. **G2 is open.** We do not yet know whether DEPI's AWS access allows an Organization with member accounts, or only one account.
2. **R5:** cross-account IAM, a delegated GuardDuty/Security Hub admin and cross-account OIDC are the most complex pieces of the build, and they sit on the critical path for a team of three.
3. Moving a multi-account design down to one account means rewriting every provider block, trust policy and bucket policy. Splitting a well-namespaced single account into several is mostly a matter of adding provider aliases.

## Decision

Implement in **one AWS account** first. Keep the boundaries that would become separate accounts as **separate Terraform modules**:

| Future account | Modules that move there, unchanged except the provider alias |
|---|---|
| Security | `log-archive`, `logging`, `detection`, `soar` |
| Workload | `network`, `ecr`, `ecs`, `edge`, `cognito`, `data` |

Rules that keep the later split cheap:

- Modules never hard-code an account ID. They use `aws_caller_identity`.
- Cross-module wiring goes only through module outputs and inputs, never `data` lookups by name.
- Every resource policy is scoped with `aws:SourceAccount` / `aws:SourceArn`, so it is already correct per account.

## Consequences

**Gained:** the critical path gets shorter, nothing waits on G2, and there is one state file to reason about.

**Lost, and must be said in the report and viva:**

- **Weaker blast-radius isolation.** In one account, an attacker holding admin in the workload *can* reach the log archive and the SOAR roles. Mitigations: SSE-KMS with key policies, versioning, optional Object Lock on the log archive (`log_archive_object_lock_days`), and least-privilege roles. In the presentation, show the multi-account diagram as the **target state**.
- **No SCPs.** Organization guardrails are not available. Account-level settings stand in for some of them (EBS encryption by default in `bootstrap/`).

## Revisit when

G2 is answered "yes, Organizations available" **and** PB-01 works end-to-end. Not before: a split in the middle of a sprint is exactly the integration risk that R6 warns about.
