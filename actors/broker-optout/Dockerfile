# AUX Broker-Opt-Out — pure logic (no network, no browser). It only builds a
# removal PLAN (STIX Observed Data + erasure letters + re-check proposal) from
# user-confirmed listings, so the lightweight Apify Node image suffices. Build
# with the REPO ROOT as the Docker context so ../../../shared require paths
# resolve. (Build context is the repo root, like the other AUX actors.)
FROM apify/actor-node:20

WORKDIR /usr/src/app

# Copy manifest first for dependency-layer caching.
COPY --chown=myuser actors/broker-optout/package.json ./actors/broker-optout/package.json

RUN cd actors/broker-optout \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

# Copy shared modules (incl. shared/aux + shared/enrich) and this actor's source.
COPY --chown=myuser shared ./shared
COPY --chown=myuser actors/broker-optout ./actors/broker-optout

WORKDIR /usr/src/app/actors/broker-optout

CMD ["node", "src/main.js"]
