FROM node:22.23.3-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS base

FROM base AS app-deps
WORKDIR /build
COPY package.json package-lock.json ./
# Use bundled Node-API prebuilds, not npm's implicit binding.gyp rebuild.
RUN npm ci --omit=dev --ignore-scripts \
    && node -e "require('better-sqlite3')(':memory:').close()"

FROM base AS app
ENV NODE_ENV=production
WORKDIR /opt/intake
RUN groupadd --gid 10001 intake-web \
    && groupadd --gid 10010 intake-sock \
    && useradd --uid 10001 --gid 10001 --groups 10010 --no-create-home intake-web \
    && useradd --uid 10002 --gid 10010 --no-create-home intake-writer \
    && install -d -o 10002 -g 10010 -m 0770 /run/intake \
    && install -d -o 10002 -g 10010 -m 2770 /var/lib/intake/public
COPY --from=app-deps /build/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY public ./public
COPY docker/healthcheck.js ./docker/healthcheck.js

FROM app AS web
ENV INTAKE_HOST=0.0.0.0
USER 10001:10001
CMD ["node", "src/web-main.js"]

FROM app AS writer
RUN install -d -o 10002 -g 10010 -m 0700 /var/lib/intake/private /run/intake-bw
COPY docker/prepare-bw-socket.js ./docker/prepare-bw-socket.js
COPY docker/writer-entrypoint.sh /usr/local/bin/intake-writer
RUN chmod 0555 /usr/local/bin/intake-writer
USER 10002:10010
ENTRYPOINT ["/usr/local/bin/intake-writer"]
CMD ["node", "src/writer-main.js"]

FROM base AS bw-deps
WORKDIR /build/bw
COPY docker/bw/package.json docker/bw/package-lock.json ./
# No native addons; the pinned tree's only lifecycle script is a core-js banner.
RUN npm ci --omit=dev --ignore-scripts

FROM base AS bw
ENV NODE_ENV=production \
    HOME=/var/lib/intake/bw \
    BITWARDENCLI_APPDATA_DIR=/var/lib/intake/bw
WORKDIR /opt/intake
RUN groupadd --gid 10010 intake-sock \
    && useradd --uid 10002 --gid 10010 --home-dir /var/lib/intake/bw --no-create-home intake-writer \
    && install -d -o 10002 -g 10010 -m 0700 /var/lib/intake/bw /run/intake-bw
COPY --from=bw-deps /build/bw/node_modules /opt/bitwarden/node_modules
RUN ln -s /opt/bitwarden/node_modules/@bitwarden/cli/build/bw.js /usr/local/bin/bw
COPY docker/bw-entrypoint.sh /usr/local/bin/intake-bw
RUN chmod 0555 /usr/local/bin/intake-bw
COPY package.json ./
COPY docker/prepare-bw-socket.js ./docker/prepare-bw-socket.js
COPY docker/healthcheck.js ./docker/healthcheck.js
USER 10002:10010
ENTRYPOINT ["/usr/local/bin/intake-bw"]
