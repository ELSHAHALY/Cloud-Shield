# Local equivalents of the CI gates — run before you push.
# Requires: terraform, gitleaks, semgrep, trivy, checkov on PATH.

TF_DIRS := infra/terraform/bootstrap $(wildcard infra/terraform/environments/*) $(wildcard infra/terraform/modules/*)
TF_TEST_DIRS := $(patsubst %/tests,%,$(wildcard infra/terraform/modules/*/tests))

PYTHON ?= python3

.PHONY: help scan secrets sast sca iac fmt validate test gate-selftest soar-lint soar-test package-soar sim ir-report expired-blocks \
        app-lint app-test app-build dockerlint local-up local-down local-seed local-smoke local-moto

help:
	@echo "make scan           - every local gate (secrets, sast, sca, iac, soar)"
	@echo "make fmt            - terraform fmt -recursive"
	@echo "make validate       - terraform validate every root and module (no backend)"
	@echo "make test           - offline terraform test suites (mocked AWS)"
	@echo "make gate-selftest  - prove each gate trips on a seeded bad input"
	@echo "make soar-lint      - ruff on the SOAR Lambdas"
	@echo "make soar-test      - SOAR unit tests (moto) with coverage gate"
	@echo "make package-soar   - deterministic Lambda zip -> build/soar-playbooks.zip"
	@echo "make sim            - attack sim: SCENARIO=a|a-recon|b|c|d|e MODE=replay [TARGET=local|aws]"
	@echo "make ir-report      - IR report from an incident: INCIDENT=<id> [FMT=md|json]"
	@echo "make expired-blocks - audit PB-05 IP blocks: expired, lost, orphans (read-only)"
	@echo "make app-lint       - ESLint + tsc + OpenAPI drift for docs-api, spa, local-dev"
	@echo "make app-test       - Jest (docs-api, local-dev; needs moto: make local-moto) + Vitest (spa)"
	@echo "make app-build      - docs-api image + SPA production build (bundle check)"
	@echo "make dockerlint     - hadolint + Checkov on the app Dockerfiles"
	@echo "make local-up       - docker compose local stack; UI on http://localhost:3000"
	@echo "make local-smoke    - end-to-end checks against the local stack"
	@echo "make local-down     - stop the local stack and drop its data"

scan: secrets sast sca iac soar-lint soar-test app-lint app-test dockerlint

secrets:
	gitleaks git . --redact --verbose

sast:
	semgrep scan --config p/owasp-top-ten --config p/nodejs --config p/python --config p/typescript --config p/react --severity ERROR --error --metrics off --exclude infra/ --exclude docs/

# pip install -r soar/requirements-dev.txt first.
soar-lint:
	cd soar && ruff check . ../scripts/package_soar.py && ruff format --check . ../scripts/package_soar.py

soar-test:
	cd soar && $(PYTHON) -m pytest --cov

# Upload the zip to a versioned bucket, then set soar_playbook_package
# { s3_bucket, s3_key, s3_object_version } in environments/dev.
package-soar:
	$(PYTHON) scripts/package_soar.py --out build/soar-playbooks.zip

sca:
	trivy fs --scanners vuln --severity CRITICAL --ignore-unfixed --exit-code 1 --skip-dirs infra --skip-dirs "**/node_modules" .

iac: fmt validate test
	checkov -d infra/terraform --framework terraform --quiet --compact

fmt:
	terraform fmt -recursive infra/terraform

validate:
	@for d in $(TF_DIRS); do \
	  echo "== validate $$d"; \
	  terraform -chdir=$$d init -backend=false -input=false >/dev/null && \
	  terraform -chdir=$$d validate || exit 1; \
	done

test:
	@for d in $(TF_TEST_DIRS); do \
	  echo "== test $$d"; \
	  terraform -chdir=$$d init -backend=false -input=false >/dev/null && \
	  terraform -chdir=$$d test || exit 1; \
	done

gate-selftest:
	scripts/gate-selftest.sh all

# Attack simulation (plan §7). Offline default; AWS targets need credentials.
# e.g. make sim SCENARIO=c ACCOUNT=123456789012 NAME=cloudshield-dev SIM_ARGS="--bucket-name cloudshield-dev-lab-exposure-123456789012"
# D/E (D20): replay --target local only, and only while the SSM dry-run switch reads true:
#   make sim SCENARIO=e ACCOUNT=123456789012 SIM_ARGS="--ip <client-ip>"
#   make sim SCENARIO=d ACCOUNT=123456789012 SIM_ARGS="--task-arn <arn> --service-name docs-api"
SCENARIO ?= a-recon
MODE     ?= replay
TARGET   ?= local
REGION   ?= us-east-1
NAME     ?= cloudshield-dev
sim:
	cd soar && $(PYTHON) -m sims.runner --scenario $(SCENARIO) --mode $(MODE) --target $(TARGET) --allowed-account $(ACCOUNT) --region $(REGION) --name $(NAME) $(SIM_ARGS)

# Incident Response report (FR-8). Needs dynamodb:GetItem + s3:GetObject.
FMT ?= md
ir-report:
	cd soar && $(PYTHON) -m tools.generate_ir_report $(INCIDENT) --table $(NAME)-soar-incidents --format $(FMT)

# PB-05 block audit (D15): expired / lost / orphan entries. Read-only: never
# calls UpdateIPSet (the sweeper Lambda lifts expired blocks).
# Needs dynamodb:Scan + kms:Decrypt (SOAR key) + wafv2:GetIPSet.
expired-blocks:
	cd soar && $(PYTHON) -m tools.list_expired_blocks --table $(NAME)-soar-incidents --region $(REGION) --format $(if $(filter json,$(FMT)),json,text)

# ---- Phase E: app (docs-api, spa, local-dev) and the local stack ----
APP_PKGS := app/docs-api app/spa app/local-dev
COMPOSE  := docker compose -f docker-compose.local.yml
HADOLINT_IMAGE ?= hadolint/hadolint:v2.14.0

app-lint:
	@for d in $(APP_PKGS); do echo "== lint $$d"; (cd $$d && npm ci --ignore-scripts >/dev/null && npm run lint && npm run typecheck) || exit 1; done
	cd app/docs-api && npm run openapi:check

# Jest suites marked *.int.test.ts need moto on MOTO_ENDPOINT (default http://localhost:5000).
app-test:
	cd app/docs-api && npx jest --coverage
	cd app/local-dev && npx jest
	cd app/spa && npx vitest run --coverage

app-build:
	docker build --platform linux/amd64 -f app/docs-api/Dockerfile -t cloudshield/app:local app
	cd app/spa && VITE_AUTH_MODE=cognito VITE_COGNITO_USER_POOL_ID=us-east-1_Placeholder VITE_COGNITO_CLIENT_ID=placeholder npm run build && node scripts/check-bundle.mjs dist

dockerlint:
	@for f in app/docs-api/Dockerfile app/spa/Dockerfile app/local-dev/Dockerfile; do echo "== $$f"; \
	  docker run --rm -i -v "$$PWD:/w:ro" -w /w $(HADOLINT_IMAGE) hadolint --config /w/.hadolint.yaml $$f || exit 1; done
	checkov -d app --framework dockerfile --quiet --compact

# moto alone, for the Jest integration suites.
local-moto:
	docker run -d --rm --name cloudshield-moto -p 127.0.0.1:5000:5000 motoserver/moto:5.2.4

local-up:
	$(COMPOSE) up -d --build --wait --wait-timeout 300

local-seed:
	$(COMPOSE) run --rm seed

local-smoke:
	cd app/local-dev && npm ci --ignore-scripts >/dev/null && npm run build >/dev/null && \
	  AWS_ACCESS_KEY_ID=local-only AWS_SECRET_ACCESS_KEY=local-only node dist/smoke.js

local-down:
	$(COMPOSE) down -v --remove-orphans
