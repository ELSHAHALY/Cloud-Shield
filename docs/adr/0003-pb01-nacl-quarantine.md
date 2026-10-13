# ADR-0003: PB-01 cuts established connections with a worker-tier NACL deny

- **Status:** Accepted (14 Oct 2026)
- **Deciders:** S3 (owner), S1 (network module co-owner)
- **Relates to:** handoff §3 gap **10**, plan §6.5 (Figure 6.5), `soar/README.md` PB-01 notes

## Context

PB-01 isolates a compromised instance by swapping its security groups onto the empty quarantine SG. Security groups are **stateful**: connections already tracked when the swap happens stay open until they go idle. In scenario A, an attacker's session would survive the isolation and the playbook would still report CONTAINED. That is gap 10.

Three fixes were considered:

| Option | Why not, or why |
|---|---|
| **Per-IP NACL rule** for the instance's private IP | Doesn't work. A NACL is evaluated at the subnet boundary: inbound rules match the packet's *source* and outbound rules its *destination*. A rule naming the instance's own IP, in its own subnet's NACL, never matches that instance's traffic. |
| **SSM `SendCommand`** to kill processes or flush conntrack | The quarantine SG blocks the agent's own 443 egress, so the command must run *before* the swap. That is slower and relies on an agent on a host that may already be compromised. It also needs `ssm:SendCommand`, a remote-execution permission. |
| **Deny-all NACL entries on a dedicated worker-tier NACL** | NACLs are stateless, so every packet is re-evaluated and established flows stop at once. It takes one IAM action (`ec2:CreateNetworkAclEntry`) on one resource ARN. |

## Decision

- `modules/network` gives the `private_worker` subnets their own NACL, with allow-all rules at **100** in and out. That is the default NACL's behaviour, so nothing changes until PB-01 acts.
- PB-01 `isolate` adds `deny 0.0.0.0/0, all protocols` at rule **10**, ingress and egress, **before** the SG swap.
- The rule number is `var.quarantine_nacl_rule_number`, validated to 1–99.
- IAM grants `ec2:CreateNetworkAclEntry` only on the NACL ARNs passed in `quarantine_network_acl_ids`.
  - `ReplaceNetworkAclEntry` and `DeleteNetworkAclEntry` are **not** granted, so the playbook can only add rules. It can never loosen the allow at 100 or remove a quarantine.
  - The Lambda also refuses any NACL that isn't in its `QUARANTINE_NACL_IDS` allow-list.
- `contained: true` requires both deny entries, the quarantine-only SG and both instance protections to read back correctly from AWS.

## Consequences

- **Blast radius = the whole worker tier** (both worker subnets). Today the only resource there is the report-worker. Anything placed in those subnets later is quarantined together with it, so keep other workloads out of them. App subnets keep the default NACL and are never touched.
- The quarantined instance is unreachable, including through Session Manager. Forensics works from the EBS snapshots that PB-01 `snapshot` takes after CONTAINED.
- **Recovery is human** (plan §6.4, automation stops at CONTAINED). After eradication, an analyst removes the entries:

  ```bash
  aws ec2 delete-network-acl-entry --network-acl-id <acl-id> --rule-number 10 --ingress
  aws ec2 delete-network-acl-entry --network-acl-id <acl-id> --rule-number 10 --egress
  ```

  Then restore the instance's SGs from the `sg-swap` action on the incident row (`previousGroups`), and delete the inline policy `cloudshield-soar-revoke-older-sessions` from the worker role.
- `terraform apply` doesn't manage the deny entries (they aren't in state), so an apply never silently lifts a quarantine.
