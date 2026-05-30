# A2 Discovery — no browser needed. Build with REPO ROOT as the Docker context
# so shared/ resolves through the ../../../shared require paths.
FROM apify/actor-node:20

WORKDIR /usr/src/app

COPY actors/discovery/package.json ./actors/discovery/package.json

RUN cd actors/discovery \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

COPY shared ./shared
COPY actors/discovery ./actors/discovery

WORKDIR /usr/src/app/actors/discovery

CMD ["node", "src/main.js"]
