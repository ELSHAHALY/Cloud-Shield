# 2. Literature review and benchmarking

| Field | Value |
|---|---|
| Report | CloudShield capstone report (DEPI AWS Cloud Security, Fall 2026) |
| Chapter | 02 of 07 |
| Version | 1.0 |
| Date | 17 Oct 2026 |
| Status | DRAFT |
| Owners | S1 @ELSHAHALY, S2 @YasseenAbdelghany, S3 @ahklsfg (jointly) |
| Reviewers | Each owner reviews the sections outside their own domain; the Phase F Independent Auditor (plan §11) |
| Sources and marks | See the legend in [`docs/reports/README.md` §2](README.md#2-sources-and-marks-legend); numbers policy in [§3](README.md#3-numbers-policy) |

> **What is measured vs pending (this chapter)**
> - **Measured:** nothing. This chapter reviews sources and compares designs; it reports no measurement.
> - **Not yet verified:** every external reference `[L1]…[L21]` carries `[verify: edition, date, URL; link not checked]`. The links could not be checked from the build sandbox, whose proxy refused outbound connections on 17 Oct 2026. Every commercial product and AWS solution name carries `[verify]` for current naming and status.
> - **Deliberately absent:** statistics, market figures, survey results and prices from any source (plan D17).

---

## 2.1 Method

### 2.1.1 Question

The review asks three things:

1. Which established standards and primary guidance describe the practices that CloudShield implements: secure software delivery, container and supply-chain security, incident response and digital forensics, and cloud security architecture?
2. Where does CloudShield follow that guidance, where does it deviate on purpose, and where does it fall short?
3. How does a two-loop design (build-time gates plus runtime containment) compare, qualitatively, with a single-loop DevOps pipeline, with commercial SOAR platforms and with the incident-response samples and solutions that AWS publishes?

### 2.1.2 Inclusion and exclusion criteria

| Criterion | Included | Excluded |
|---|---|---|
| Publisher | Standards bodies and their programmes (NIST, ISO/IEC, OWASP, MITRE, CIS, Ecma International, the OpenSSF SLSA project); the cloud provider's own primary documentation (AWS whitepapers and prescriptive guidance); two widely used practitioner books | Blogs, vendor marketing, analyst reports, preprints, any source not on the approved list in plan §6.4 |
| Content used | Process models, control objectives, terminology and recommended practices | Statistics, survey results, market sizes, benchmarks of tools, prices |
| Edition | The edition the authors believe current, marked `[verify]` | — |

The approved list is fixed by plan §6.4 [repo: docs/plans/depi-phase-f-capstone-complete.md §6.4]. No source outside it is cited. Product and solution names in §2.5.2 and §2.5.3 are not literature: they are compared at the level of documented capabilities and deployment model, and each name is marked `[verify]`.

### 2.1.3 Verification policy

Each reference in §2.7 gives the title, publisher, the edition and year as the authors believe them, the URL, and the mark `[verify: edition, date, URL; link not checked]`. Access dates read "accessed —, to be filled when verified". The descriptions of what each source contains are written from the authors' knowledge of the documents and kept at the level of structure and intent (for example, the phases of a lifecycle), not quotation. The mark stays until a team member has opened the official document, confirmed the edition and the statement attributed to it, and recorded the access date. A claim that turns out to be wrong is corrected or removed; it is never left in with the mark removed.

### 2.1.4 How claims about CloudShield are supported

Every statement about what CloudShield does points to a file in this repository. Where the behaviour depends on AWS and has not been observed, it is written as design intent ("is designed to"), because nothing has been applied to AWS [repo: docs/HANDOFF.md §1].

### 2.1.5 Threats to validity of this review

- **Edition drift.** Several sources were revised recently or have revisions in progress (NIST SP 800-61, OWASP Top 10, OWASP ASVS, SLSA, ISO/IEC 27035). An edition named here may have been superseded; every edition is `[verify]`.
- **Recall, not re-reading.** Source descriptions were written without re-opening the documents in this session. The `[verify]` mark covers this.
- **Vendor capabilities change quickly.** The qualitative comparison in §2.5.2 and §2.5.3 is a snapshot of the authors' understanding and is `[verify]` throughout.
- **No empirical comparison.** No product in §2.5 was installed or tested. The comparison is of documented design, not of measured performance.

---

## 2.2 DevSecOps foundations

### 2.2.1 Secure software development: NIST SSDF (SP 800-218) [L3]

The Secure Software Development Framework groups practices into four families: prepare the organisation (PO), protect the software (PS), produce well-secured software (PW) and respond to vulnerabilities (RV) [L3]. It is outcome-oriented: it says what a producer should achieve, not which tool to run, which makes it a good yardstick for a small team's pipeline.

CloudShield's pipeline maps onto the four families as follows. Practice identifiers are given at family level only; finer practice ids are `[verify]` against [L3].

| SSDF family [L3] | CloudShield practice | Repo evidence |
|---|---|---|
| PO: prepare the organisation | Roles and ownership per domain; review rules; documented decisions | [repo: .github/CODEOWNERS]; [repo: docs/adr/]; [repo: .github/pull_request_template.md] |
| PS: protect the software | Third-party actions pinned to full commit SHAs; images pinned by digest; ECR tags immutable; no long-lived CI keys (GitHub OIDC) | [repo: .github/workflows/ci.yml header]; [repo: infra/terraform/modules/compute/variables.tf `container_image` validation]; [repo: infra/terraform/modules/compute/main.tf `aws_ecr_repository.app`]; [repo: infra/terraform/bootstrap/main.tf §2] |
| PW: produce well-secured software | SAST (Semgrep), SCA (Trivy fs), IaC policy (Checkov), image scan (Trivy image), DAST (ZAP baseline), secrets scanning (Gitleaks, full history); contract-first API; tests with coverage gates | [repo: .github/workflows/ci.yml]; [repo: app/openapi.yaml]; [repo: soar/pyproject.toml] |
| RV: respond to vulnerabilities | Dependabot for actions, Terraform providers, npm packages and Docker images; the gate self-test that proves each gate trips | [repo: .github/dependabot.yml]; [repo: scripts/gate-selftest.sh] |

**Where CloudShield falls short of the SSDF's intent.** There is no signed release or provenance attestation (PS family), and no recorded vulnerability-disclosure process (RV family). Both are listed as follow-ups in §2.6.

### 2.2.2 DevSecOps reference platform: NIST SP 800-204C [L4]

SP 800-204C describes DevSecOps for a cloud-native application built from microservices with a service mesh. It treats the pipeline as a set of code types, each with its own CI/CD flow: application code, application services code, infrastructure as code, policy as code and observability as code [L4] [verify]. Its value for CloudShield is the idea that infrastructure and policy are code that goes through the same gates as the application.

CloudShield applies that idea without a service mesh. Infrastructure is Terraform with offline `terraform test` suites and Checkov in the same pipeline as the application [repo: .github/workflows/ci.yml job `iac`]. Policy appears as code in three places: the Checkov skip list with an inline reason for every skip [repo: docs/HANDOFF.md §3 gap 4], the ZAP rule file [repo: .zap/rules.tsv], and the GRC rules as versioned data evaluated by a constrained condition language [repo: app/grc/README.md]. The SOAR state machine is also code: its route table is shared by Terraform tests and pytest so the two cannot drift [repo: docs/HANDOFF.md §12 A6]. There is no service mesh, so the mesh-specific parts of [L4] (mutual TLS between services, mesh-level authorisation) do not apply; the single service authenticates each request itself [repo: app/README.md "Identity and request contract"].

### 2.2.3 OWASP DevSecOps Guideline [L9]

The OWASP DevSecOps Guideline is a practical description of which security checks belong in a pipeline (secrets scanning, SAST, SCA, IaC scanning, container scanning, DAST) and of introducing them gradually [L9] [verify]. CloudShield follows the same progression and makes the gradual part explicit: every gate starts fail-open and becomes blocking when the repository variable `ENFORCE_GATES` is `true` [repo: .github/workflows/ci.yml header "FAIL-OPEN vs ENFORCED"]. The guideline's emphasis on running cheap checks first is reflected in the job order "secrets → SAST → SCA → IaC → image → DAST" [repo: .github/workflows/ci.yml header].

One CloudShield detail goes beyond what a fail-open design normally records: each scan exports its real outcome, so a job can stay green in fail-open mode while the image push still requires that every scan succeeded [repo: .github/workflows/ci.yml job `secrets` `outputs.scan`, job `image`; docs/HANDOFF.md §12 A9].

### 2.2.4 OWASP Top 10 [L8] and OWASP ASVS [L10]

The OWASP Top 10 (2021 edition) is an awareness list of web-application risk categories [L8]. Whether a newer edition has been finalised must be checked, and if so the mapping below re-done [verify]. The repository already uses its categories: the SAST gate runs the `p/owasp-top-ten` Semgrep pack [repo: .github/workflows/ci.yml job `sast`], and the SCA job is labelled "OWASP A06" [repo: .github/workflows/ci.yml, Gate 3 comment].

| OWASP Top 10 (2021) category [L8] | CloudShield control | Repo evidence |
|---|---|---|
| A01 Broken Access Control | Tenant taken only from the verified token; cross-tenant requests answer 404; RBAC from verified groups | [repo: app/README.md "Identity and request contract"] |
| A03 Injection | Semgrep SAST; request validation from the OpenAPI contract | [repo: .github/workflows/ci.yml job `sast`]; [repo: app/openapi.yaml] |
| A05 Security Misconfiguration | Checkov on Terraform and Dockerfiles; ZAP header rules set to FAIL | [repo: .github/workflows/ci.yml job `iac`]; [repo: .zap/rules.tsv] |
| A06 Vulnerable and Outdated Components | Trivy fs on lockfiles; Trivy image; Dependabot | [repo: .github/workflows/ci.yml jobs `sca`, `image`]; [repo: .github/dependabot.yml] |
| A07 Identification and Authentication Failures | Cognito with TOTP MFA and admin-only sign-up; API re-verifies signature, `iss`, `aud` and `token_use` | [repo: docs/HANDOFF.md §12 "What was built"]; [repo: app/README.md] |
| A08 Software and Data Integrity Failures | SHA-pinned actions, digest-pinned images, CycloneDX SBOM | [repo: .github/workflows/ci.yml job `image`] |
| A09 Security Logging and Monitoring Failures | Audit event for every state change; CloudTrail with S3 data events | [repo: app/README.md]; [repo: infra/terraform/modules/detection/cloudtrail.tf] |
| A10 Server-Side Request Forgery | IMDSv2 required on the report-worker, which scenario A attacks | [repo: infra/terraform/modules/compute/worker.tf `metadata_options`] |

The Application Security Verification Standard is the more detailed companion: a list of verifiable requirements grouped by area (authentication, session management, access control, validation, and so on) at increasing assurance levels [L10]. Its current version must be checked [verify]. CloudShield has not been assessed against ASVS requirement by requirement; chapter 05 is the place where such an assessment would be recorded. The review notes it as a gap rather than claiming a level.

### 2.2.5 Containers: NIST SP 800-190 [L5]

SP 800-190 organises container risk by component (image, registry, orchestrator, container runtime, host operating system) and gives countermeasures for each [L5]. CloudShield's choices line up with the image and registry countermeasures:

| SP 800-190 area [L5] | CloudShield | Repo evidence |
|---|---|---|
| Image vulnerabilities and configuration | Distroless Node 24 base, non-root user `1000:1000`, base images pinned by digest; Trivy image scan with fixable CRITICAL/HIGH failing; hadolint and Checkov on Dockerfiles | [repo: app/docs-api/Dockerfile]; [repo: .github/workflows/ci.yml job `image`] |
| Registry | ECR with immutable tags, scan on push, KMS encryption; push only through an OIDC role limited to `main` | [repo: infra/terraform/modules/compute/main.tf `aws_ecr_repository.app`]; [repo: infra/terraform/modules/compute/ci-push.tf] |
| Orchestrator | ECS Fargate (no hosts to manage); task definition with read-only root filesystem; deployment only by digest | [repo: infra/terraform/modules/compute/service.tf `readonlyRootFilesystem`]; [repo: infra/terraform/modules/compute/variables.tf `container_image`] |
| Container runtime | GuardDuty Runtime Monitoring feeds PB-04 when switched on (paid, off by default) | [repo: README.md feature-flag table]; [repo: docs/adr/0005-pb04-pb05-edge-and-ecs-containment.md] |
| Host OS | Not applicable to Fargate in the shared-responsibility split | [L13] [verify] |

### 2.2.6 Supply-chain integrity: SLSA [L15] and CycloneDX [L16]

SLSA defines levels of assurance for how an artefact was built, centred on build provenance: a verifiable statement of what was built, from which source, by which builder [L15] [verify edition: v1.0 or v1.1]. CloudShield produces **no provenance attestation** [repo: .github/workflows/ci.yml job `image`, which produces an SBOM and pushes, with no attestation step]. It therefore claims **no SLSA level**. What it has are the preconditions a provenance step would build on: a hosted builder, a single workflow definition under review, pinned actions, and a push identity limited to the `main` branch [repo: infra/terraform/modules/compute/ci-push.tf]. A self-assessment against SLSA belongs in chapter 04 and is marked [inferred, not certified] there.

CycloneDX is a bill-of-materials format, standardised by Ecma International as ECMA-424 [L16] [verify]. The image gate generates a CycloneDX SBOM with Trivy and keeps it as a build artefact for 90 days [repo: .github/workflows/ci.yml job `image`, steps "Generate SBOM (CycloneDX)" and "Upload SBOM", `retention-days: 90`]. The SBOM is not yet signed, attached to the image in the registry, or consumed by a later step; it is an inventory for review.

### 2.2.7 Cloud configuration baseline: CIS AWS Foundations Benchmark [L17]

The CIS Amazon Web Services Foundations Benchmark is a consensus configuration baseline for an AWS account, covering identity, storage, logging, monitoring and networking [L17] [verify]. The repository names version 3.0.0, which is the standard the optional Security Hub subscription enables [repo: infra/terraform/modules/detection/main.tf `aws_securityhub_standards_subscription.cis`]. Security Hub is off by default because of its per-check cost [repo: infra/terraform/modules/detection/variables.tf `enable_security_hub`], so no CIS score exists.

Several CloudShield defaults correspond to controls of the kind the benchmark contains: a multi-region CloudTrail trail [repo: infra/terraform/modules/detection/cloudtrail.tf `is_multi_region_trail`], KMS key rotation on every customer-managed key (§1.8.2 of chapter 01), EBS encryption by default [repo: infra/terraform/bootstrap/main.tf §4], VPC flow logs [repo: infra/terraform/modules/network/main.tf `aws_flow_log`], and Block Public Access on every bucket. One deviation is deliberate: account-level S3 Block Public Access is **not** set, because it would silently override the bucket-level change that attack scenario C makes, and the scenario would never fire [repo: infra/terraform/bootstrap/main.tf §4 comment]. Whether the benchmark recommends the account-level setting in this edition is [verify]; if it does, the deviation is recorded as an accepted exception for a lab account.

### 2.2.8 Delivery performance and feedback: *Accelerate* [L20] and *The DevOps Handbook* [L21]

*Accelerate* frames software delivery performance in terms of throughput and stability measures, one of which is the time to restore service after a failure [L20] [verify]. *The DevOps Handbook* describes the "Three Ways": flow from development to operations, fast feedback from operations back to development, and continual learning [L21] [verify]. Neither book is a security standard; they matter here because CloudShield's two loops are an instance of the second Way applied to security: runtime findings produce artefacts that flow back into code (§2.5.1). This chapter quotes no figure from either book. CloudShield's MTTC is a narrower measure than time to restore: it ends at verified containment and deliberately excludes eradication and recovery [repo: docs/adr/0002-module-map-and-scaffold-strategy.md §3]; see [README §5](README.md#5-mttc-definition-and-measurement-classes).

---

## 2.3 Incident response and forensics

### 2.3.1 NIST SP 800-61: the incident-handling lifecycle [L1], [L2]

Revision 2 of SP 800-61 describes incident handling as a lifecycle of four phases: preparation; detection and analysis; containment, eradication and recovery; and post-incident activity [L1]. It treats containment as a decision with explicit criteria (for example, the need to preserve evidence and the potential damage of each strategy) and separates it from eradication and recovery [L1] [verify].

Revision 3 recasts incident response as part of cybersecurity risk management and organises its recommendations around the six Functions of NIST CSF 2.0, as a CSF 2.0 Community Profile [L2] [verify]. The two revisions are used side by side here: Revision 2's lifecycle is the clearer model for an automated responder, and Revision 3 places that responder in a governance context.

| SP 800-61 Rev. 2 phase [L1] | CloudShield implementation | Automated? | Repo evidence |
|---|---|---|---|
| Preparation | Safety guard rules, scope tag, permissions boundary, dry-run switch on by default, runbooks, attack simulations behind R4 gates | Configuration, not runtime | [repo: soar/README.md "Safety guard rules"]; [repo: docs/runbooks/]; [repo: soar/sims/safety.py] |
| Detection and analysis | GuardDuty findings; Config non-compliance; WAF rate-limit harvester; the notify-only decoy; Athena hunt queries; deterministic ATT&CK triage | Detection yes; analysis partly (triage), hunting is human | [repo: infra/terraform/modules/detection/]; [repo: detection/athena-queries/]; [repo: soar/core/attack.py] |
| Containment | PB-01…PB-05 behind the guard; `CONTAINED` only after read-back verification | **Yes** | [repo: infra/terraform/modules/soar/state-machine.tf `CheckContained`, `MarkContained`] |
| Eradication and recovery | Human steps in runbooks and in the IR report; the PB-05 sweeper only expires blocks | **No, by design** | [repo: docs/adr/0003-pb01-nacl-quarantine.md]; [repo: docs/runbooks/pb04-pb05-recovery.md]; [repo: soar/core/attack.py `eradication`, `recovery`] |
| Post-incident activity | IR report with chain-of-custody check, MTTC and a Terraform remediation snippet for PB-03 | Report generation is automated; the review is human | [repo: soar/tools/generate_ir_report.py] |

This split is what the repository means by **automated containment with human-gated eradication** [repo: docs/HANDOFF.md §2.1]. SP 800-61's separation of containment from eradication is the reason the automation boundary sits where it does: containment can be made safe by narrowing it (scope tag, verification, dry-run), whereas eradication needs judgement about root cause and collateral effects.

### 2.3.2 AWS Security Incident Response Guide [L12]

The AWS whitepaper adapts incident response to AWS: preparing people, process and technology in advance; using the provider's own telemetry (CloudTrail, VPC Flow Logs, GuardDuty and others); automating repeatable response steps; and acquiring forensic artefacts such as volume snapshots from isolated resources [L12] [verify]. CloudShield follows these patterns in its playbooks: PB-01 swaps the instance onto an empty quarantine security group, adds a deny-all to the dedicated worker-tier NACL because security groups are stateful and do not cut tracked connections, and snapshots the volumes after containment [repo: soar/README.md "PB-01 notes"; docs/adr/0003-pb01-nacl-quarantine.md]. Whether the guide itself discusses the connection-tracking limitation is [verify]; the repository's reasoning does not depend on it.

### 2.3.3 Digital evidence: NIST SP 800-86 [L6] and ISO/IEC 27037 [L19]

SP 800-86 describes forensics within incident response as collection, examination, analysis and reporting, with the integrity of collected data protected and demonstrable throughout, for example by message digests and a documented chain of custody [L6] [verify]. ISO/IEC 27037 gives guidelines for identifying, collecting, acquiring and preserving digital evidence [L19] [verify]. CloudShield does not claim conformance with either; it implements their central integrity idea for the evidence it produces:

| Integrity practice [L6], [L19] | CloudShield | Repo evidence |
|---|---|---|
| Preserve before analysis | Evidence capture runs after `CONTAINED` but in the same execution; PB-01 snapshots volumes, PB-03 stores the pre-state | [repo: infra/terraform/modules/soar/state-machine.tf `PB01Snapshot`, `PB03Evidence`]; [repo: soar/README.md] |
| Hash at acquisition | Canonical JSON uploaded with `ChecksumAlgorithm=SHA256`; the returned hash is written to the incident row, because a file cannot contain its own hash | [repo: soar/core/evidence.py]; [repo: soar/README.md "PB-01 notes"] |
| Keep the original | `evidenceRecords` collects every manifest; `evidenceSha256` keeps the first hash so a re-run never displaces the original | [repo: soar/README.md "PB-02 and PB-03 notes"] |
| Verify later | The IR tool and the SOC panel recompute every SHA-256 from S3 and report a broken chain (the IR tool exits non-zero) | [repo: soar/tools/generate_ir_report.py]; [repo: app/docs-api/src/soc/evidence.ts] |
| Retention | Object Lock is off by default (`evidence_object_lock_days = 0`); Phase F adds a dev pass-through so a graded lab run can turn it on before the first apply | [repo: infra/terraform/environments/dev/variables.tf, variable `evidence_object_lock_days`] |

The chain-of-custody check is tested against golden fixtures shared by the Python and TypeScript implementations, class M0 in [README §5](README.md#5-mttc-definition-and-measurement-classes) [repo: soar/tests/fixtures/coc_golden.json].

### 2.3.4 Incident management: ISO/IEC 27035 [L18]

ISO/IEC 27035 is the multi-part international standard for information security incident management: principles and process, guidelines for planning and preparing, and guidelines for response operations [L18] [verify: part numbers, editions and dates]. Its process view resembles SP 800-61's. It is cited for completeness and for the vocabulary of the GRC hub's breach-notification rules; CloudShield makes no conformance claim and the repository contains no clause-level mapping.

### 2.3.5 Adversary behaviour: MITRE ATT&CK [L11]

ATT&CK is a knowledge base of adversary tactics and techniques; the Enterprise matrix includes cloud platforms, among them IaaS [L11]. CloudShield uses technique identifiers in three places that are kept consistent by a CI check: the attack scenarios, the deterministic triage in the IR report, and the SOC dashboard's ATT&CK view [repo: soar/sims/scenarios.py; soar/core/attack.py; app/docs-api/src/soc/attack-table.generated.json; docs/HANDOFF.md §13 "SOAR" row].

| Technique id | Name [L11] [verify] | Scenario | Playbook | Repo evidence |
|---|---|---|---|---|
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | A | PB-01 | [repo: soar/sims/scenarios.py "a"] |
| T1046 | Network Service Discovery | A, A-recon | PB-01 | [repo: soar/sims/scenarios.py "a", "a-recon"] |
| T1078 | Valid Accounts | B | PB-02 | [repo: soar/sims/scenarios.py "b"] |
| T1552.001 | Unsecured Credentials: Credentials In Files | B | PB-02 | [repo: soar/sims/scenarios.py "b"] |
| T1530 | Data from Cloud Storage | C | PB-03 | [repo: soar/sims/scenarios.py "c"] |
| T1610 | Deploy Container | D | PB-04 | [repo: soar/sims/scenarios.py "d"] |
| T1059 | Command and Scripting Interpreter | D | PB-04 | [repo: soar/sims/scenarios.py "d"] |
| T1496 | Resource Hijacking | D (cryptocurrency findings) | PB-04 | [repo: soar/core/attack.py `_runtime`] |
| T1190 | Exploit Public-Facing Application | E | PB-05 | [repo: soar/sims/scenarios.py "e"] |
| T1595 | Active Scanning | E | PB-05 | [repo: soar/sims/scenarios.py "e"] |
| T1499 | Endpoint Denial of Service | E (triage only) | PB-05 | [repo: soar/core/attack.py `_SCENARIO_E`] |

The repository does not record which ATT&CK version the mapping was made against. Recording it, and re-checking each name (ATT&CK renames and splits techniques between versions), is a follow-up [verify].

---

## 2.4 Cloud security architecture

### 2.4.1 AWS Well-Architected Framework, Security Pillar [L13]

The Security Pillar states design principles for workloads on AWS, among them a strong identity foundation, traceability, security at every layer, automated security best practices, protection of data in transit and at rest, keeping people away from data, and preparing for security events [L13] [verify]. It also sets out the shared responsibility model: AWS is responsible for the security *of* the cloud and the customer for security *in* the cloud [L13] [verify].

| Design principle [L13] [verify] | CloudShield | Repo evidence |
|---|---|---|
| Strong identity foundation | Cognito with TOTP MFA and an immutable tenant claim; GitHub OIDC instead of CI keys; least-privilege task and Lambda roles | [repo: infra/terraform/modules/identity/]; [repo: infra/terraform/bootstrap/main.tf §2] |
| Enable traceability | CloudTrail with S3 data events on the sensitive buckets; insert-only-by-convention audit table with a stream; flow logs; WAF logs | [repo: infra/terraform/modules/detection/cloudtrail.tf]; [repo: infra/terraform/modules/data/main.tf] |
| Security at all layers | Edge WAFs, API Gateway authorizer plus in-API token re-verification, security groups and a dedicated worker NACL, KMS on every store | [repo: docs/adr/0004-edge-identity-waf.md]; [repo: infra/terraform/modules/network/] |
| Automate security best practices | Policy and scanning gates in CI; SOAR containment | [repo: .github/workflows/ci.yml]; [repo: infra/terraform/modules/soar/] |
| Protect data in transit and at rest | TLS-only bucket policies; customer-managed KMS keys; documents bucket rejects foreign keys and the SSE-S3 header | [repo: docs/HANDOFF.md §2.4 `data`] |
| Keep people away from data | Version-pinned, short-lived pre-signed downloads; uploads only through the API | [repo: docs/HANDOFF.md §13 `app/docs-api`] |
| Prepare for security events | Playbooks, dry-run, attack simulations, runbooks, IR report | [repo: soar/]; [repo: docs/runbooks/] |

The GRC hub publishes a shared-responsibility matrix for the platform (AWS built; Azure and GCP mapped as equivalents, not built) [repo: app/grc/matrix/shared-responsibility.json; app/grc/README.md].

**Known departure.** The pillar's identity principle points towards authorisation that the platform enforces. In CloudShield, tenant isolation is enforced in the API, not by IAM or cryptography (the SSE-KMS context is the bucket ARN under S3 Bucket Keys) [repo: docs/adr/0002-module-map-and-scaffold-strategy.md §5]. The stretch goal is per-request STS session tags with `dynamodb:LeadingKeys` [repo: docs/HANDOFF.md §3 gap 11].

### 2.4.2 AWS Security Reference Architecture [L14]

The AWS SRA describes a multi-account layout under AWS Organizations, with dedicated accounts for security tooling and for log archiving, delegated administration of the security services, and workload accounts separated from both [L14] [verify]. Its central argument is blast-radius isolation: a compromised workload account should not be able to erase the evidence or switch off detection.

CloudShield is a **single AWS account (ADR-0001); the multi-account design is the target state.** ADR-0001 keeps the future account boundaries as Terraform module boundaries, so a later split moves whole modules: `log-archive`, `detection` and `soar` to a Security account; `network`, `compute`, `edge`, `identity` and `data` to a Workload account [repo: docs/adr/0001-single-account-first.md; docs/adr/0002-module-map-and-scaffold-strategy.md §1]. Compared with the SRA as summarised above, the target combines log archive and security tooling in one Security account; splitting them further is a refinement for the target state [verify against [L14]].

| SRA element [L14] [verify] | CloudShield now | CloudShield target | Repo evidence |
|---|---|---|---|
| Organizations with SCPs | None; EBS encryption by default stands in for one SCP | Organization, SCPs | [repo: docs/adr/0001-single-account-first.md "Consequences"] |
| Log archive account | `log-archive` module in the same account; optional Object Lock | Security account | [repo: infra/terraform/modules/log-archive/] |
| Security tooling account, delegated admin | GuardDuty detector in the same account; Security Hub off | Security account with delegated admin | [repo: infra/terraform/modules/detection/main.tf `aws_guardduty_detector.this` Checkov skip reason] |
| Workload account | `network`, `compute`, `edge`, `identity`, `data` | Workload account | [repo: docs/adr/0002-module-map-and-scaffold-strategy.md §1] |

What one account loses is stated in ADR-0001: an attacker holding admin in the account can reach the log archive and the SOAR roles, and there are no SCPs [repo: docs/adr/0001-single-account-first.md "Consequences"]. Chapter 03 §10 develops this.

### 2.4.3 NIST Cybersecurity Framework 2.0 [L7]

CSF 2.0 organises cybersecurity outcomes into six Functions: Govern, Identify, Protect, Detect, Respond and Recover [L7] [verify]. It is used here as a coverage map, not a conformance claim.

| CSF 2.0 Function [L7] | CloudShield | Repo evidence |
|---|---|---|
| Govern | ADRs, code ownership, review rules, the GRC hub as a self-assessment | [repo: docs/adr/]; [repo: .github/CODEOWNERS]; [repo: app/grc/README.md] |
| Identify | Config inventory of S3 buckets; the module map's trust boundaries; ATT&CK mapping | [repo: infra/terraform/modules/detection/main.tf]; [repo: docs/adr/0002-module-map-and-scaffold-strategy.md §1] |
| Protect | Cognito, KMS, WAF, the CI gates, container hardening | [repo: infra/terraform/modules/]; [repo: .github/workflows/ci.yml] |
| Detect | GuardDuty, CloudTrail, Config rules, the WAF harvester, the decoy route, Athena hunts | [repo: infra/terraform/modules/detection/]; [repo: detection/athena-queries/] |
| Respond | `cs-ir-router` and PB-01…PB-05; IR report; ChatOps notification | [repo: infra/terraform/modules/soar/]; [repo: soar/] |
| Recover | Human runbooks; DynamoDB point-in-time recovery; S3 versioning | [repo: docs/runbooks/pb04-pb05-recovery.md]; [repo: docs/adr/0003-pb01-nacl-quarantine.md]; [repo: docs/HANDOFF.md §2.4] |

---

## 2.5 Benchmarking

All three comparisons are qualitative. No product was installed, no performance was measured, and no price is given.

### 2.5.1 Against a single-loop DevOps pipeline

A single-loop pipeline here means build-time gates only: scans run on each change, and what happens after deployment is outside the pipeline's view. CloudShield adds a runtime loop and connects the two.

| Capability | Single-loop pipeline (build-time gates only) | CloudShield (two loops) | Repo evidence |
|---|---|---|---|
| Gates before merge | Yes | Yes: secrets, SAST, SCA, IaC, image, `soar`, `app`; DAST after merge, on `main` or manual dispatch, once `STAGING_URL` is set | [repo: .github/workflows/ci.yml job `dast`] |
| Gate outcome visible at runtime | Usually not | The image carries the real gate outcomes as build arguments; the SOC posture banner shows them and the ECR scan of the running digest, and never claims "no vulnerabilities" | [repo: app/docs-api/Dockerfile `ARG GATE_*`]; [repo: app/docs-api/src/posture/posture.ts]; [repo: app/spa/src/soc/PostureBanner.tsx] |
| Only gated artefacts deploy | Depends on convention | The image is pushed only when every scan really passed, and the service accepts only a digest-pinned image | [repo: .github/workflows/ci.yml job `image`]; [repo: infra/terraform/modules/compute/variables.tf `container_image` validation] |
| Runtime detection | Out of scope | GuardDuty, Config, WAF harvester, decoy | [repo: infra/terraform/modules/detection/]; [repo: infra/terraform/modules/soar/edge-bus.tf] |
| Automated containment | Out of scope | PB-01…PB-05 behind a fail-closed guard, verified before `CONTAINED` | [repo: infra/terraform/modules/soar/state-machine.tf] |
| Runtime → code feedback | None | PB-03's IR report proposes a ready-to-apply `aws_s3_bucket_public_access_block` block and the matching `terraform import`, so the restored setting is codified; PB-04's triage states that a new image must be built, scanned and deployed by digest, because `forceNewDeployment` reuses the same digest | [repo: soar/tools/generate_ir_report.py `_terraform_label` and the snippet after it]; [repo: soar/core/attack.py `_runtime`]; [repo: soar/playbooks/pb04_ecs_task_contain.py docstring] |
| Response-time measure | Not defined | MTTC defined once, with measurement classes M0–M4 | [README §5](README.md#5-mttc-definition-and-measurement-classes) |
| Evidence and audit | Build logs | Hashed evidence manifests with a recomputable chain of custody; an insert-only-by-convention audit table | [repo: soar/core/evidence.py]; [repo: infra/terraform/modules/data/main.tf] |

The link that matters most is the last one in each direction: the pipeline decides what may run, and the runtime loop's output (a remediation snippet, a rebuild instruction) can only take effect by going back through the pipeline. That is the DevOps Handbook's feedback Way [L21] applied to security. The runtime loop does not itself change the infrastructure definitions: PB-04's `forceNewDeployment` re-runs the same task definition and image digest, and building and deploying a new image is a human step [repo: docs/adr/0002-module-map-and-scaffold-strategy.md §5 "PB-04 does not eradicate"].

### 2.5.2 Against commercial SOAR platforms

Compared products (names and current status [verify]): **Splunk SOAR** [verify], **Palo Alto Networks Cortex XSOAR** [verify], **Microsoft Sentinel** automation rules and playbooks [verify], and **Google Security Operations** SOAR [verify]. Every cell in the vendor columns is the authors' qualitative understanding of each product's documentation and is [verify]; no cell states a price, a market position or a performance figure. Licensing is recorded only as "commercial".

| Dimension | Commercial SOAR platforms (general pattern) [verify] | CloudShield | Repo evidence |
|---|---|---|---|
| Deployment model | Vendor-hosted SaaS, and for some products a self-managed option; Microsoft Sentinel runs on Azure [verify] | Serverless in the customer's own AWS account: Step Functions, Lambda, DynamoDB, deployed with Terraform | [repo: infra/terraform/modules/soar/] |
| Playbook authoring | Visual playbook designers with code steps, and large libraries of vendor integrations [verify] | Python handlers plus the state machine in Terraform; every change is a pull request through the same CI gates and code-owner review | [repo: soar/]; [repo: infra/terraform/modules/soar/state-machine.tf]; [repo: .github/CODEOWNERS] |
| Guardrails | Role-based access, approval steps and test or "dry-run" modes exist in various forms [verify] | A fail-closed guard (only boolean `allowed == true` proceeds), the scope tag checked in code **and** enforced by IAM conditions and a permissions boundary, a global dry-run switch read on every call, a never-block list for IP blocks | [repo: soar/README.md "Safety guard rules"]; [repo: infra/terraform/modules/soar/playbooks.tf] |
| "Contained" semantics | Typically the playbook's own step result [verify] | `CONTAINED` only after a read-back verification returns `contained: true` | [repo: infra/terraform/modules/soar/state-machine.tf `CheckContained`] |
| Case management | Built-in cases, assignment, SLA timers, analyst collaboration [verify] | **None.** An incident row per finding and a read-only SOC dashboard; no assignment or workflow | [repo: app/spa/src/soc/]; [repo: docs/adr/0006-app-soc-grc-local.md] |
| Enrichment | Threat-intelligence and asset-context integrations [verify] | **None** beyond the finding's own fields and deterministic ATT&CK triage | [repo: soar/core/attack.py] |
| Evidence handling | Artefact storage within the case [verify] | SHA-256-checksummed manifests in a KMS-encrypted bucket, the hash on the incident row, optional Object Lock, recompute on demand | [repo: soar/core/evidence.py]; [repo: soar/tools/generate_ir_report.py] |
| Multi-cloud and integrations | Broad, through connectors [verify] | AWS only; one account | [repo: docs/adr/0001-single-account-first.md] |
| Response-time metric | Product dashboards with vendor-defined metrics [verify] | One MTTC definition with explicit start and stop states and measurement classes | [README §5](README.md#5-mttc-definition-and-measurement-classes) |
| Licensing | Commercial | Academic capstone repository (no licence file in the repository) | [repo: repository root] |

The comparison is not a claim that CloudShield competes with these platforms. They solve the analyst-workflow problem at scale; CloudShield is a narrowly scoped, auditable containment engine whose behaviour can be reviewed line by line and whose safety rests on infrastructure-level bounds rather than on playbook discipline.

### 2.5.3 Against AWS samples and solutions

Compared (names and status [verify]): **Automated Security Response on AWS** [verify], **Automated Forensic Orchestrator for Amazon EC2** [verify], the **aws-samples incident-response playbooks** [verify], and the **AWS Security Incident Response** service [verify]. Descriptions are qualitative and [verify].

| Solution [verify] | What it does, as the authors understand it [verify] | Relation to CloudShield |
|---|---|---|
| Automated Security Response on AWS | Remediation runbooks triggered from Security Hub findings, deployable across accounts [verify] | Overlaps on automated remediation; CloudShield triggers from GuardDuty and edge events, not Security Hub controls, and stops at containment |
| Automated Forensic Orchestrator for Amazon EC2 | Orchestrated forensic acquisition from EC2 instances in response to findings [verify] | Overlaps with PB-01's isolate-then-snapshot; CloudShield captures volume snapshots and manifests, not memory |
| aws-samples incident-response playbooks | Written playbook templates for common AWS incident types [verify] | Comparable to CloudShield's runbooks and the IR report's eradication and recovery steps; documents, not automation |
| AWS Security Incident Response (service) | A managed service for triage, case handling and access to AWS responders [verify] | Provides the case management and human response that CloudShield deliberately leaves out; complementary |

**What CloudShield adds,** relative to the descriptions above [verify]:

| Design choice | Repo evidence |
|---|---|
| A fail-closed guard double-bound by the scope tag in code and by IAM conditions and a permissions boundary, so a guard bug cannot widen what a playbook may touch | [repo: soar/README.md "Safety guard rules"]; [repo: infra/terraform/modules/soar/playbooks.tf `scope_condition_key`, `iam:PermissionsBoundary`] |
| Verify-before-contained: `CONTAINED` is reachable only through `CheckContained` | [repo: infra/terraform/modules/soar/state-machine.tf]; [HANDOFF §5] |
| An explicit MTTC clock from the EventBridge `time` to `MarkContained`, with evidence capture outside it | [repo: infra/terraform/modules/soar/state-machine.tf `RecordDetected`, `MarkContained`]; [repo: docs/adr/0002-module-map-and-scaffold-strategy.md §3] |
| Evidence after containment, hashed, with the first hash kept on the row | [repo: soar/README.md]; [repo: soar/core/evidence.py] |
| A notify-only decoy route: hits are recorded and notified, never blocked, because the guard refuses the type | [repo: soar/core/finding.py `EDGE_NOTIFY_ONLY_TYPES`]; [repo: app/docs-api/src/decoy/router.ts] |
| A Regional GRC hub that evaluates rules as data and exports a Compliance Readiness Pack: a self-assessment, not an audit ("Not legal advice. Not an audit or certification.") | [repo: app/grc/README.md]; [repo: app/spa/src/grc/readinessPack.ts] |

**What CloudShield lacks:** case management, enrichment, multi-account deployment and any scale testing. None of the four AWS offerings above was evaluated hands-on, so these lists are design comparisons only.

### 2.5.4 Synthesis

Read together, the sources pull in two directions that CloudShield has to reconcile. The incident-response literature ([L1], [L12]) treats containment as a decision: the right strategy depends on what is at stake, what evidence must be preserved and what the action will break. The DevOps literature ([L20], [L21]) and the DevSecOps guidance ([L3], [L9]) favour automation, fast feedback and repeatability. An automated responder satisfies the second only by narrowing the first: it may decide alone only where the decision has been made in advance and can be checked mechanically.

CloudShield's answer is to make that narrowing explicit and enforceable rather than a matter of playbook discipline. The decision about *which* resources automation may touch is encoded twice, once as a tag the guard checks and once as IAM conditions that hold even if the guard is wrong [repo: soar/README.md "Safety guard rules"]. The decision about *whether* an action worked is made by reading AWS back, not by trusting the API call's return [repo: infra/terraform/modules/soar/state-machine.tf `CheckContained`]. The decisions that need judgement (eradication, recovery, lifting a quarantine) are left to people, with the runbooks and the IR report as their inputs [repo: docs/adr/0003-pb01-nacl-quarantine.md; soar/tools/generate_ir_report.py].

The benchmark also shows the cost of that narrowness. Commercial platforms and the AWS managed service cover the analyst's whole workflow, including cases, enrichment and collaboration; CloudShield covers only the containment stage of a small set of well-defined incident types in one account. That is an appropriate scope for a capstone whose central claim is about safety and verifiability, provided the report does not present it as more. It also means the most important evidence for the design, MTTC and containment on real AWS resources (classes M3 and M4), does not exist yet; the benchmark can show that the design is distinctive, not that it performs.

---

## 2.6 Gap statement and design goals

The review and the benchmarks point to a gap that CloudShield is designed to address: build-time gates and runtime response are usually separate systems, and where response is automated, the evidence that an action was safe, verified and fast is often implicit. The design goals below follow from that gap. The "status" column states what is shown today; nothing on AWS is shown yet [repo: docs/HANDOFF.md §1].

| Gap (from §2.2–§2.5) | Design goal | Implementation | Status |
|---|---|---|---|
| Build-time and runtime security are separate loops (§2.5.1; [L21]) | DG1: link the loops in both directions | Gate outcomes in the image and the posture banner; push only on real success; digest-only deploys; IaC snippet and rebuild guidance from the IR report | Built and tested locally and in CI; posture on AWS pending first apply |
| Automated containment can act on the wrong target ([L1] containment criteria) | DG2: bound automation by construction | Fail-closed guard, scope tag, IAM conditions, permissions boundary, dry-run on by default | Built; tested in CI under moto; IAM behaviour on AWS pending first apply |
| A playbook's success can be assumed rather than shown | DG3: verify before claiming containment | `CheckContained` and read-back verification in every playbook | Built; tested in CI under moto |
| Response time is reported without a definition | DG4: define and class the metric | MTTC definition and classes M0–M4 ([README §5](README.md#5-mttc-definition-and-measurement-classes)) | M0–M2 exist; M3/M4 pending first apply |
| Evidence integrity is hard to demonstrate later ([L6], [L19]) | DG5: hash at acquisition, verify on demand | Checksummed manifests, the hash on the row, recompute in two implementations with golden fixtures | Built; tested against golden fixtures (M0) and seeded data (M1) |
| Compliance tooling can be mistaken for an audit | DG6: honest compliance support | GRC rules as data with `verify` badges; the Compliance Readiness Pack as a self-assessment, not an audit | Built; legal items open [repo: docs/HANDOFF.md §13] |
| Multi-account isolation is the reference architecture ([L14]) but on the critical path | DG7: single account now, boundaries preserved | Single AWS account (ADR-0001); the multi-account design is the target state | Accepted trade-off |
| No provenance or SLSA level ([L15]); no ASVS assessment ([L10]); ATT&CK version not recorded ([L11]) | Follow-ups | — | Open |

---

## 2.7 Rubric mapping

The DEPI rubric is not in the repository.

| Rubric criterion | Section of this chapter |
|---|---|
| [source: plan PDF, not in repo — team to verify] | |
| [source: plan PDF, not in repo — team to verify] | |

---

## 2.8 References

All entries: accessed —, to be filled when verified. Editions and years are as the authors believe them.

| Id | Title | Publisher | Edition / year (as believed) | URL | Mark |
|---|---|---|---|---|---|
| L1 | Computer Security Incident Handling Guide, SP 800-61 Rev. 2 | NIST | Rev. 2, 2012 | https://csrc.nist.gov/pubs/sp/800/61/r2/final | [verify: edition, date, URL; link not checked] |
| L2 | Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile, SP 800-61 Rev. 3 | NIST | Rev. 3, 2025 | https://csrc.nist.gov/pubs/sp/800/61/r3/final | [verify: edition, date, URL; link not checked] |
| L3 | Secure Software Development Framework (SSDF) Version 1.1, SP 800-218 | NIST | v1.1, 2022 | https://csrc.nist.gov/pubs/sp/800/218/final | [verify: edition, date, URL; link not checked] |
| L4 | Implementation of DevSecOps for a Microservices-based Application with Service Mesh, SP 800-204C | NIST | 2022 | https://csrc.nist.gov/pubs/sp/800/204/c/final | [verify: edition, date, URL; link not checked] |
| L5 | Application Container Security Guide, SP 800-190 | NIST | 2017 | https://csrc.nist.gov/pubs/sp/800/190/final | [verify: edition, date, URL; link not checked] |
| L6 | Guide to Integrating Forensic Techniques into Incident Response, SP 800-86 | NIST | 2006 | https://csrc.nist.gov/pubs/sp/800/86/final | [verify: edition, date, URL; link not checked] |
| L7 | The NIST Cybersecurity Framework (CSF) 2.0, CSWP 29 | NIST | 2.0, 2024 | https://www.nist.gov/cyberframework | [verify: edition, date, URL; link not checked] |
| L8 | OWASP Top 10 | OWASP Foundation | 2021 (check whether a newer edition is final) | https://owasp.org/Top10/ | [verify: edition, date, URL; link not checked] |
| L9 | OWASP DevSecOps Guideline | OWASP Foundation | current project version | https://owasp.org/www-project-devsecops-guideline/ | [verify: edition, date, URL; link not checked] |
| L10 | OWASP Application Security Verification Standard (ASVS) | OWASP Foundation | 4.0.3 or later (check the current version) | https://owasp.org/www-project-application-security-verification-standard/ | [verify: edition, date, URL; link not checked] |
| L11 | MITRE ATT&CK Enterprise Matrix, Cloud / IaaS | The MITRE Corporation | version to be recorded | https://attack.mitre.org/matrices/enterprise/cloud/iaas/ | [verify: edition, date, URL; link not checked] |
| L12 | AWS Security Incident Response Guide (whitepaper) | Amazon Web Services | current online version | https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html | [verify: edition, date, URL; link not checked] |
| L13 | AWS Well-Architected Framework, Security Pillar | Amazon Web Services | current online version | https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html | [verify: edition, date, URL; link not checked] |
| L14 | AWS Security Reference Architecture (AWS SRA) | Amazon Web Services (Prescriptive Guidance) | current online version | https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html | [verify: edition, date, URL; link not checked] |
| L15 | SLSA specification | OpenSSF SLSA project | v1.0 (check whether v1.1 is current) | https://slsa.dev/spec/v1.0/ | [verify: edition, date, URL; link not checked] |
| L16 | CycloneDX Bill of Materials Specification, ECMA-424 | Ecma International / OWASP CycloneDX | ECMA-424, 1st edition (check the current edition) | https://ecma-international.org/publications-and-standards/standards/ecma-424/ | [verify: edition, date, URL; link not checked] |
| L17 | CIS Amazon Web Services Foundations Benchmark | Center for Internet Security | v3.0.0 (the version the repo's Security Hub flag names) | https://www.cisecurity.org/benchmark/amazon_web_services | [verify: edition, date, URL; link not checked] |
| L18 | ISO/IEC 27035, Information technology — Information security incident management (multi-part) | ISO/IEC | parts 1–3; check current editions | https://www.iso.org/standard/78973.html | [verify: edition, date, URL; link not checked] |
| L19 | ISO/IEC 27037, Guidelines for identification, collection, acquisition and preservation of digital evidence | ISO/IEC | 2012 | https://www.iso.org/standard/44381.html | [verify: edition, date, URL; link not checked] |
| L20 | *Accelerate: The Science of Lean Software and DevOps* (N. Forsgren, J. Humble, G. Kim) | IT Revolution Press | 2018 | — (book) | [verify: edition, date, URL; link not checked] |
| L21 | *The DevOps Handbook*, 2nd ed. (G. Kim, J. Humble, P. Debois, J. Willis, N. Forsgren) | IT Revolution Press | 2nd ed., 2021 | — (book) | [verify: edition, date, URL; link not checked] |
