# Taban imajların kaynağı. Docker Hub limitine takılırsan:
#   docker build --build-arg BASE_REGISTRY=mirror.gcr.io/library -t underworld-city .
ARG BASE_REGISTRY=docker.io/library

# ---------- 1) Flutter web istemcisini derle ----------
FROM ${BASE_REGISTRY}/debian:bookworm-slim AS web
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl git xz-utils unzip ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ARG FLUTTER_VERSION=3.47.9
RUN curl -fsSL "https://storage.googleapis.com/flutter_infra_release/releases/stable/linux/flutter_linux_${FLUTTER_VERSION}-stable.tar.xz" \
    | tar -xJ -C /opt \
 && git config --global --add safe.directory /opt/flutter
ENV PATH="/opt/flutter/bin:${PATH}"
RUN flutter config --no-analytics >/dev/null && flutter precache --web
WORKDIR /app/client
COPY client/pubspec.yaml client/pubspec.lock ./
RUN flutter pub get
COPY client/ ./
RUN flutter build web --release

# ---------- 2) Node sunucusu ----------
FROM ${BASE_REGISTRY}/node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server.js ./
COPY src ./src
COPY --from=web /app/client/build/web ./client/build/web
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD node -e "fetch('http://localhost:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
