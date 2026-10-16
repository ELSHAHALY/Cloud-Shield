# DEV ONLY (plan D22, §10): the local IdP and the moto seed for
# docker-compose.local.yml. Never built by CI's image gate, never pushed.
# Build context: app/ (the seed reads grc/agreements to hash the texts).

FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS build
WORKDIR /app/local-dev
COPY local-dev/package.json local-dev/package-lock.json local-dev/.npmrc ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY local-dev/tsconfig.json local-dev/tsconfig.build.json ./
COPY local-dev/src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts --no-audit --no-fund

FROM gcr.io/distroless/nodejs24-debian13:nonroot@sha256:59c479c9b8c123e66047315c968aa2d35e31ae5149c856e4110a79c8b3563f0b AS runtime
WORKDIR /app/local-dev
ENV NODE_ENV=production
COPY --from=build /app/local-dev/node_modules ./node_modules
COPY --from=build /app/local-dev/dist ./dist
COPY local-dev/fixtures ./fixtures
COPY grc/agreements /app/grc/agreements
USER 1000:1000

FROM runtime AS idp
EXPOSE 9000
HEALTHCHECK --interval=5s --timeout=2s --retries=10 CMD ["/nodejs/bin/node", "dist/healthcheck.js"]
CMD ["dist/idp.js"]

FROM runtime AS seed
HEALTHCHECK NONE
CMD ["dist/seed.js"]
