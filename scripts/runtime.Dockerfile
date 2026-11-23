FROM mirror.gcr.io/library/node@sha256:0e2646ab57e77b7a384a0cb59b6815b182c77e1f9c3ba36bd8435bd9c4e6680e

RUN test "$(node --version)" = 'v24.22.3' \
    && npm install --global --registry=https://registry.npmjs.org --no-audit --no-fund openclaw@2026.11.7 \
    && test "$(node -p 'require("/usr/local/lib/node_modules/openclaw/package.json").version')" = '2026.11.7'
