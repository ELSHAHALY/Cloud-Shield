# soar/sims/ — attack simulations (plan §7, risk R4)

Drives scenarios A–C through the SOAR pipeline to prove detection → containment, and to measure MTTC. The hunt queries (`detection/athena-queries/`) and the IR report (`soar/tools/generate_ir_report.py`) read the incidents these runs produce.

## Safety first (risk R4 — AWS Abuse)

Every run passes `sims/safety.py` before any AWS call:

1. the caller's account must be given with `--allowed-account` (no default);
2. the client must have a resolved region equal to `--region` (an unset region fails closed);
3. before any pipeline call, each named target's **live tags are read** and it must carry `cloudshield:soar-scope=in-scope` — and, for name-identified targets (buckets, IAM users), also match the `--name` prefix (EC2 instances are identified by an opaque id, so there the tag is the sole marker);
4. `--mode live-aws` also needs `--confirm-live <account-id>`, the account retyped;
5. the sim only ever names resources it looked up in this account — never an external host.

If any gate fails the runner exits `3` and does nothing. This target check (`sims.safety.verify_targets`) is independent of the pipeline's own guard, so it holds even if the SOAR `SafetyGuard` is misconfigured.

> **`--target local` still calls AWS.** It drives the real playbook handlers, which read and (when dry-run is off) mutate AWS through whatever client is configured — against moto in the test suite, against the live account otherwise. The safety gates above run first regardless; keep the SSM dry-run switch on until you mean to act.

## Modes

| Mode | AWS? | What it does |
|---|---|---|
| `replay --target local` | no (CI) | Drives an in-process copy of `cs-ir-router` (guard → route → playbook → contained check) against moto or a real account read path. Its routing table is contract-tested against `state-machine.tf`. |
| `replay --target aws` | yes | `StartExecution` on the real `cs-ir-router` with an event aimed at the live lab target, `time = now`. Polls the execution and the incident row; asserts the expected status and **MTTC < 60 s** (when dry-run is off). |
| `live-aws` | yes | The reversible attacker action; waits for GuardDuty's own finding to drive the pipeline. Operator-run (not automated here); steps below. |

Exit code `0` = passed, `1` = ran but did not meet the bar, `3` = a safety gate refused.

```bash
# offline smoke test (what CI runs)
make sim SCENARIO=c ACCOUNT=123456789012 NAME=cloudshield-dev \
     SIM_ARGS="--bucket-name cloudshield-dev-lab-exposure-123456789012"

# against the deployed lab (needs credentials + the lab-targets module)
python -m sims.runner --scenario c --mode replay --target aws \
    --allowed-account 123456789012 --region us-east-1 --name cloudshield-dev \
    --state-machine-arn arn:aws:states:...:stateMachine:cloudshield-dev-cs-ir-router \
    --bucket-name cloudshield-dev-lab-exposure-123456789012
```

## Scenarios (MITRE ATT&CK)

| Scenario | Technique | Replay event | Live action |
|---|---|---|---|
| `a` | T1552.005, T1046 | `InstanceCredentialExfiltration.OutsideAWS` naming the real worker + its role id | **Decision D4:** live containment with a replayed detection. The credentials never leave the instance. |
| `a-recon` | T1046 | `Recon:EC2/Portscan` on the worker | the worker's lab scan window (`allow_worker_lab_scan`) |
| `b` | T1078, T1552.001 | `UnauthorizedAccess:IAMUser/*` naming the honeytoken user + a key created for the run | create a key on the honeytoken, make low-value calls, wait for a finding. If none arrives in the window, report "no detection" — never claim it. |
| `c` | T1530 | `Policy:S3/BucketBlockPublicAccessDisabled` on the lab bucket | turn the lab bucket's BPA off (no public policy, no data). PB-03 restores it; the sim restores it too if PB-03 hasn't within the window. |

Scenarios B and C need the `lab-targets` module (`enable_lab_targets = true`): a honeytoken user carrying the SOAR target boundary (PB-02 needs it to count as contained), and a tagged `*-lab-exposure` bucket. No access key is ever stored in Terraform state — the sim creates and deletes it at runtime.

## Why live A is replayed detection (decision D4)

A genuine `InstanceCredentialExfiltration.OutsideAWS` finding requires the worker role's credentials to be used from outside AWS, which means moving them to an operator machine (they would pass through SSM command output). We don't do that. Instead `replay --target aws` runs the **real** PB-01 against the **real** worker — true isolation, true MTTC — with a synthetic finding. Detection of the exfiltration path itself is demonstrated separately with GuardDuty sample findings (dry-run only, by guard rule 2).

## Cleanup

Live modes clean up in a `finally:` block and expose `cleanup` too (idempotent, needs `--yes`): Block Public Access back on, runtime honeytoken keys deleted, and the ADR-0003 NACL/SG recovery for a quarantined instance. Always run it after a live session.
