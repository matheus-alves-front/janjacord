# syntax=docker/dockerfile:1.7
ARG NODE_IMAGE=node:24.17.0-alpine3.23

FROM ${NODE_IMAGE} AS build
WORKDIR /workspace
RUN npm install --global pnpm@10.25.0
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY tsconfig.base.json turbo.json ./
COPY apps/rendezvous/package.json apps/rendezvous/package.json
COPY packages/crypto-core/package.json packages/crypto-core/package.json
COPY packages/crypto/package.json packages/crypto/package.json
COPY packages/protocol/package.json packages/protocol/package.json
COPY packages/schemas/package.json packages/schemas/package.json
RUN pnpm install --frozen-lockfile --filter @janjacord/rendezvous...
COPY packages/crypto-core packages/crypto-core
COPY packages/crypto packages/crypto
COPY packages/protocol packages/protocol
COPY packages/schemas packages/schemas
COPY apps/rendezvous apps/rendezvous
RUN pnpm --filter @janjacord/rendezvous... build \
    && pnpm --filter @janjacord/rendezvous deploy --legacy --prod /opt/rendezvous

FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production
WORKDIR /opt/janjabridge/app
COPY --from=build --chown=node:node /opt/rendezvous/ ./
COPY --chown=node:node infra/docker/scripts/rendezvous-healthcheck.mjs ./healthcheck.mjs
USER node
EXPOSE 8920
CMD ["node", "dist/main.js"]
