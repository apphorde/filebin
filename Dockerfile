FROM ghcr.io/cloud-cli/node:latest

COPY --chown=1000 . .
USER 0
RUN pnpm i && pnpm run build
