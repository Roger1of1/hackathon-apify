# A5 Diff & Evidence — no browser needed. Build with REPO ROOT as Docker context.
FROM apify/actor-node:20

WORKDIR /usr/src/app

COPY actors/diff-evidence/package.json ./actors/diff-evidence/package.json

RUN cd actors/diff-evidence \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

COPY shared ./shared
COPY actors/diff-evidence ./actors/diff-evidence

WORKDIR /usr/src/app/actors/diff-evidence

CMD ["node", "src/main.js"]
