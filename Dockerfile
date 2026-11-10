# HEM Playground: the simulator, the public site, the admin panel and the Manager, in one Node process.
FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=8080 MANAGER_DIR=/app/manager
# what the sign-in page and the public footer show: v1.0.0 (a6bb741), given by deploy/deploy.sh
ARG PG_VERSION=
ARG PG_COMMIT=
ENV PG_VERSION=$PG_VERSION PG_COMMIT=$PG_COMMIT
# openssl 3.5: HashML-DSA and external mu (node:crypto has pure ML-DSA only)
RUN apk add --no-cache openssl
COPY server ./server
COPY manager/index.html manager/favicon.svg ./manager/
COPY manager/app ./manager/app
COPY manager/sdk/hem-sdk.js manager/sdk/hem-sdk.browser.js ./manager/sdk/
RUN node -e "require('crypto').generateKeyPairSync('ml-kem-768')" && chown -R node:node /app
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- --header 'Host: health.invalid' http://127.0.0.1:8080/healthz || exit 1
CMD ["node", "server/index.mjs"]
