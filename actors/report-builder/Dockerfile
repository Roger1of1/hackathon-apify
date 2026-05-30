# A6 Report Builder — no browser needed. Build with REPO ROOT as Docker context.
FROM apify/actor-node:20

WORKDIR /usr/src/app

COPY actors/report-builder/package.json ./actors/report-builder/package.json

RUN cd actors/report-builder \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

COPY shared ./shared
COPY actors/report-builder ./actors/report-builder

WORKDIR /usr/src/app/actors/report-builder

CMD ["node", "src/main.js"]
