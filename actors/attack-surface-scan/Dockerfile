# AUX Attack-Surface Self-Scan — pure HTTP (got-scraping), no browser needed, so
# use the lightweight Apify Node image. Build with REPO ROOT as the Docker
# context so the ../../../shared and ../../../shared/aux require paths resolve.
FROM apify/actor-node:20

WORKDIR /usr/src/app

# Copy manifest first for dependency-layer caching.
COPY --chown=myuser actors/attack-surface-scan/package.json ./actors/attack-surface-scan/package.json

RUN cd actors/attack-surface-scan \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

# Copy shared modules (incl. shared/aux) and this actor's source.
COPY --chown=myuser shared ./shared
COPY --chown=myuser actors/attack-surface-scan ./actors/attack-surface-scan

WORKDIR /usr/src/app/actors/attack-surface-scan

CMD ["node", "src/main.js"]
