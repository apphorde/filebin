FROM ghcr.io/cloud-cli/image-node:latest

COPY --chown=1000 . .
USER 0
RUN pnpm i && pnpm run build
USER 1000
