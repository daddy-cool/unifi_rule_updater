# syntax=docker/dockerfile:1.7

FROM oven/bun:1-alpine AS deps
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

FROM oven/bun:1-alpine AS runtime
WORKDIR /app

ARG PORT=3000
ENV NODE_ENV=production \
    PORT=${PORT}

COPY --from=deps /app/node_modules ./node_modules
COPY package.json tsconfig.json ./
COPY src ./src
COPY public ./public

RUN mkdir -p /app/config && chown -R bun:bun /app
USER bun

EXPOSE ${PORT}
VOLUME ["/app/config"]

CMD ["bun", "src/server.ts"]
