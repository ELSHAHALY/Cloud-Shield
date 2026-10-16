# Runbook: ChatOps notifier setup (Slack or Discord)

- **Owner:** S3 (@ahklsfg) · **Relates to:** plan §5.1, ADR-0005 (D16), `soar/README.md` (notifier)
- **What you get:** a short card in a chat channel for every incident the router notifies: incident id, finding type, ATT&CK ids, status, MTTC, resource type. Email notifications keep working; the notifier is additive.

## The secret rule (D16)

An incoming-webhook URL is a **credential**: anyone holding it can post into your channel. It lives in exactly one place, an SSM **SecureString** encrypted with the SOAR key. It is never written to `terraform.tfvars`, Terraform state, a plan, the repository, a ticket or a chat message. Terraform only knows the parameter **name**, and the notifier logs only the host.

## 1. Create the webhook

- **Slack:** create an app with *Incoming Webhooks* for the SOC channel and copy its webhook URL (host `hooks.slack.com`).
- **Discord:** channel settings → Integrations → Webhooks → New webhook → copy the URL (host `discord.com`).

The notifier accepts only an `https://` URL whose host is **exactly** in `chatops_allowed_hosts` (default `hooks.slack.com` and `discord.com`), on port 443, with no user name or password in it. It never follows a redirect and ignores proxy settings.

## 2. Store it as a SecureString under the SOAR key

From a trusted workstation, with credentials for the target account:

```bash
NAME=cloudshield-dev                       # the environment's name prefix
read -rs WEBHOOK                           # paste the URL, press Enter: not echoed, not in shell history
aws ssm put-parameter \
  --name "/$NAME/soar/chatops_webhook" \
  --type SecureString \
  --key-id "alias/$NAME-soar" \
  --value "$WEBHOOK" \
  --overwrite
unset WEBHOOK
```

`--key-id alias/<name>-soar` matters: the notifier's role may decrypt with the SOAR key only, so a parameter encrypted with any other key is unreadable and every post fails closed (`posted: false`). (On a shared host, `--value` is briefly visible in the process list; use a single-user workstation.)

## 3. Turn the notifier on

In `infra/terraform/environments/dev/terraform.tfvars` (the name is not a secret):

```hcl
chatops_webhook_param_name = "/cloudshield-dev/soar/chatops_webhook"
```

The notifier ships in the SOAR zip, so `soar_playbook_package` must be set too. Then `terraform plan` and apply. Expect `<name>-soar-notifier`, its role, log group, an SNS subscription (protocol `lambda`) on the incidents topic and an `sns.amazonaws.com` invoke permission scoped to that topic.

To allow a different chat host, change `chatops_allowed_hosts` on `module "soar"` (exact host names only; no wildcards). That is a reviewed code change, not a tfvars edit.

## 4. Test

```bash
cd infra/terraform/environments/dev
aws sns publish --topic-arn "$(terraform output -raw soar_sns_topic_arn)" \
  --message "Incident chatops-test-1 | Test:Runbook/ChatOpsCheck | resource None | see table runbook"
aws logs tail "/aws/lambda/cloudshield-dev-soar-notifier" --since 10m
```

The channel shows a card for `chatops-test-1` with status `UNKNOWN (no row)`; the log shows `"notifier": "posted"` with the host and HTTP status, and **never** the URL. Messages that are neither a router string nor a GuardDuty event (Config notifications, for example) are logged as `ignored`.

| Log line | Meaning | Fix |
|---|---|---|
| `webhook-unreadable` | the parameter is missing, empty, or not decryptable with the SOAR key | step 2 (check `--key-id`) |
| `webhook-refused` | the URL breaks the outbound policy (scheme, host, port, userinfo) | use the provider's https URL; check `chatops_allowed_hosts` |
| `post-failed` with `HTTPError` | the provider answered an error or a redirect | regenerate the webhook |
| `rejected` with a status | non-2xx from the provider | check the channel and webhook still exist |

## Rotate or revoke

- **Rotate:** create a new webhook, repeat step 2 (`--overwrite`), then revoke the old one at the provider. Running containers keep the cached URL for up to 5 minutes.
- **Leaked URL:** revoke it at the provider **first**, then rotate.
- **Turn off:** set `chatops_webhook_param_name = ""` and apply. Deleting the parameter (`aws ssm delete-parameter`) is permanent; do it only after the provider-side webhook is revoked.
