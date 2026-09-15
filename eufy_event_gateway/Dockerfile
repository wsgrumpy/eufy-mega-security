FROM node:24-alpine

ARG BUILD_VERSION
ARG BUILD_ARCH

ENV EUFY_GATEWAY_VERSION=$BUILD_VERSION

LABEL \
  io.hass.version="$BUILD_VERSION" \
  io.hass.type="app" \
  io.hass.arch="$BUILD_ARCH"

RUN apk add --no-cache \
  ca-certificates \
  jq

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.build.json ./
COPY src ./src

RUN npm run build && npm prune --omit=dev

COPY run-e31-test.sh /run-e31-test.sh
RUN chmod a+x /run-e31-test.sh

CMD ["/run-e31-test.sh"]