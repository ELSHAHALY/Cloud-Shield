# SPA image for docker-compose.local.yml ONLY (target `local`, plan §10/§11):
# a local-auth build served by unprivileged nginx with the edge's headers.
# Deployed SPAs are a static `vite build` (VITE_AUTH_MODE=cognito) uploaded to
# the SPA bucket; this image is never pushed. Build context: app/spa.

FROM node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5 AS build
WORKDIR /spa
COPY package.json package-lock.json .npmrc ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json vite.config.ts index.html ./
COPY scripts ./scripts
COPY src ./src
ENV VITE_AUTH_MODE=local
RUN npm run build

FROM nginxinc/nginx-unprivileged:stable-alpine@sha256:782bb89768cc87b7f95c18b95baa1af250e5d451f26794f59363540161147c01 AS local
COPY nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=build /spa/dist /usr/share/nginx/html
USER 101
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=2s --retries=10 CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]
