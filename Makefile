# Local equivalents of the CI gates — run before you push.
# Requires: terraform, gitleaks, semgrep, trivy, checkov on PATH.

TF_DIRS := infra/terraform/bootstrap $(wildcard infra/terraform/environments/*) $(wildcard infra/terraform/modules/*)
TF_TEST_DIRS := $(patsubst %/tests,%,$(wildcard infra/terraform/modules/*/tests))

PYTHON ?= python3

.PHONY: help scan secrets sast sca iac fmt validate test gate-selftest soar-lint soar-test package-soar sim ir-report

help:
	@echo "make scan           - every local gate (secrets, sast, sca, iac, soar)"
	@echo "make fmt            - terraform fmt -recursive"
	@echo "make validate       - terraform validate every root and module (no backend)"
	@echo "make test           - offline terraform test suites (mocked AWS)"
	@echo "make gate-selftest  - prove each gate trips on a seeded bad input"
	@echo "make soar-lint      - ruff on the SOAR Lambdas"
	@echo "make soar-test      - SOAR unit tests (moto) with coverage gate"
	@echo "make package-soar   - deterministic Lambda zip -> build/soar-playbooks.zip"
	@echo "make sim            - attack sim: SCENARIO=a|a-recon|b|c MODE=replay [TARGET=local|aws]"
	@echo "make ir-report      - IR report from an incident: INCIDENT=<id> [FMT=md|json]"

scan: secrets sast sca iac soar-lint soar-test

secrets:
	gitleaks git . --redact --verbose

sast:
	semgrep scan --config p/owasp-top-ten --config p/nodejs --config p/python --severity ERROR --error --metrics off --exclude infra/ --exclude docs/

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
	trivy fs --scanners vuln --severity CRITICAL --ignore-unfixed --exit-code 1 --skip-dirs infra .

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
