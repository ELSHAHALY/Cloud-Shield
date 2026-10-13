## What & why
<!-- One or two sentences. Link the WBS item / issue. -->

## Domain
- [ ] S1 Infra / DevSecOps
- [ ] S2 App / Identity
- [ ] S3 SecOps / SOAR

## Security checklist
- [ ] No secrets, account IDs, or real emails committed (Gitleaks runs, but don't rely on it)
- [ ] New AWS resources are tagged and encrypted at rest
- [ ] IAM changes follow least privilege — no `*` actions on `*` resources without a written reason
- [ ] Any `#checkov:skip` has a reason that would survive the viva
- [ ] If this touches SOAR: the safety guard still blocks sample findings and untagged resources

## Evidence
<!-- terraform plan summary, screenshots, test output — what a reviewer needs to approve without re-running it -->
