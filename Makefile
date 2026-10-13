# Local equivalents of the CI gates — run before you push.
# Requires: terraform, gitleaks, semgrep, trivy, checkov on PATH.

TF_DIRS := infra/terraform/bootstrap $(wildcard infra/terraform/environments/*) $(wildcard infra/terraform/modules/*)
TF_TEST_DIRS := $(patsubst %/tests,%,$(wildcard infra/terraform/modules/*/tests))

.PHONY: help scan secrets sast sca iac fmt validate test gate-selftest

help:
	@echo "make scan           - every local gate (secrets, sast, sca, iac)"
	@echo "make fmt            - terraform fmt -recursive"
	@echo "make validate       - terraform validate every root and module (no backend)"
	@echo "make test           - offline terraform test suites (mocked AWS)"
	@echo "make gate-selftest  - prove each gate trips on a seeded bad input"

scan: secrets sast sca iac

secrets:
	gitleaks git . --redact --verbose

sast:
	semgrep scan --config p/owasp-top-ten --config p/nodejs --severity ERROR --error --metrics off --exclude infra/ --exclude docs/

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
