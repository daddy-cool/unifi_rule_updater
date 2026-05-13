# syntax=docker/dockerfile:1.7

FROM oven/bun:1-alpine
WORKDIR /app

# su-exec lets the entrypoint drop privileges from root to PUID/PGID before
# starting bun. Without it we can't honor the runtime-supplied user mapping.
RUN apk add --no-cache su-exec

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

ARG PORT=3000
ENV NODE_ENV=production \
    PORT=${PORT} \
    PUID=1000 \
    PGID=1000

COPY package.json tsconfig.json ./
COPY src ./src
COPY public ./public
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

RUN mkdir -p /app/config

EXPOSE ${PORT}
VOLUME ["/app/config"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["bun", "src/server.ts"]
