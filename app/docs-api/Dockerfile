# docs-api production image (plan §11). Build context: app/ (IMAGE_CONTEXT),
# so the contract (openapi.yaml) and the GRC data are inside it; the
# allow-list is Dockerfile.dockerignore next to this file (BuildKit).
#   docker build -f app/docs-api/Dockerfile app
# Runs as 1000:1000 with a read-only root filesystem (task definition, F11).

FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS build
WORKDIR /app/docs-api
COPY docs-api/package.json docs-api/package-lock.json docs-api/.npmrc ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY docs-api/tsconfig.json docs-api/tsconfig.build.json ./
COPY docs-api/src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts --no-audit --no-fund

COPY docs-api/scripts/write-build-info.mjs ./scripts/write-build-info.mjs
ARG GIT_SHA=local
ARG BUILD_TIME=""
ARG CI_RUN_ID=""
ARG GATE_SECRETS=unknown
ARG GATE_SAST=unknown
ARG GATE_SCA=unknown
ARG GATE_APP=unknown
ARG GATES_ENFORCED=false
RUN GIT_SHA="$GIT_SHA" BUILD_TIME="$BUILD_TIME" CI_RUN_ID="$CI_RUN_ID" \
    GATE_SECRETS="$GATE_SECRETS" GATE_SAST="$GATE_SAST" GATE_SCA="$GATE_SCA" GATE_APP="$GATE_APP" \
    GATES_ENFORCED="$GATES_ENFORCED" node scripts/write-build-info.mjs > build-info.json

# distroless (Debian 13): no shell, no package manager, no npm at runtime. The
# Debian 12 variant carried fixable CRITICAL/HIGH libssl3 CVEs (Oct 2026). The
# build stage stays on bookworm: it never ships and there are no native addons.
FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:59c479c9b8c123e66047315c968aa2d35e31ae5149c856e4110a79c8b3563f0b
WORKDIR /app/docs-api
ENV NODE_ENV=production \
    CLOUDSHIELD_ENV=aws
# Owned by root and not writable by the runtime user.
COPY --from=build /app/docs-api/package.json ./package.json
COPY --from=build /app/docs-api/node_modules ./node_modules
COPY --from=build /app/docs-api/dist ./dist
COPY --from=build /app/docs-api/build-info.json ./build-info.json
COPY openapi.yaml /app/openapi.yaml
COPY grc/schema /app/grc/schema
COPY grc/rules /app/grc/rules
COPY grc/matrix /app/grc/matrix
COPY grc/agreements /app/grc/agreements
COPY grc/platform-facts.json /app/grc/platform-facts.json
USER 1000:1000
EXPOSE 3000
# ECS ignores this (the NLB checks /healthz); kept for Checkov CKV_DOCKER_2 and local runs.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/nodejs/bin/node", "dist/healthcheck.js"]
CMD ["dist/server.js"]
