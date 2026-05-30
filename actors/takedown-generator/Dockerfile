# AUX Takedown-Generator — pure in-memory transform (no fetch, no browser), so
# use the lightweight Apify Node image. Build with the REPO ROOT as the Docker
# context so the ../../../shared and ../../../shared/aux require paths resolve.
FROM apify/actor-node:20

WORKDIR /usr/src/app

# Copy manifest first for dependency-layer caching.
COPY --chown=myuser actors/takedown-generator/package.json ./actors/takedown-generator/package.json

RUN cd actors/takedown-generator \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

# Copy shared modules (incl. shared/aux) and this actor's source.
COPY --chown=myuser shared ./shared
COPY --chown=myuser actors/takedown-generator ./actors/takedown-generator

WORKDIR /usr/src/app/actors/takedown-generator

CMD ["node", "src/main.js"]
