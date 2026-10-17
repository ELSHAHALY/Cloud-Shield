# Runbook: deploy the SPA to the SPA bucket (Phase E)

**Owner:** S2 build, S1 apply. The SPA is a **static build**; there is no SPA container in AWS.

## 1. Build with the Cognito settings

```bash
cd infra/terraform/environments/dev
terraform output -json spa_build_environment
# {"VITE_AWS_REGION":"us-east-1","VITE_COGNITO_CLIENT_ID":"…","VITE_COGNITO_USER_POOL_ID":"us-east-1_…"}

cd ../../../../app/spa
npm ci --ignore-scripts
VITE_AUTH_MODE=cognito \
VITE_COGNITO_USER_POOL_ID=<from output> \
VITE_COGNITO_CLIENT_ID=<from output> \
VITE_AWS_REGION=us-east-1 \
npm run build
node scripts/check-bundle.mjs dist     # must print "bundle ok": no local-idp, no inline script/style
```

These are public identifiers, not secrets. Never build a deployable SPA with `VITE_AUTH_MODE=local`.

## 2. Upload

```bash
BUCKET=$(terraform -chdir=../../infra/terraform/environments/dev output -raw spa_bucket_name)
aws s3 sync dist/assets "s3://$BUCKET/assets" --cache-control "public, max-age=31536000, immutable"
aws s3 cp dist/index.html "s3://$BUCKET/index.html" --cache-control "no-cache"
```

Hashed asset names make the long cache safe; `index.html` is always revalidated.

## 3. Invalidate and check

```bash
DIST=$(terraform -chdir=../../infra/terraform/environments/dev output -raw cloudfront_distribution_id)
aws cloudfront create-invalidation --distribution-id "$DIST" --paths /index.html
```

Then, in a browser on the CloudFront URL: sign in (SRP + TOTP), and open the developer console: there must be **no CSP violation** (the edge CSP is `default-src 'self'`, `connect-src 'self' https://cognito-idp.<region>.amazonaws.com`). Plan §16 item 12 is this check. If an output name above differs, `terraform output` lists them.
