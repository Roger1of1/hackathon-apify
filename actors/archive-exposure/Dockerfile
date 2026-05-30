# AUX Public-Archive Self-Exposure Audit — pure HTTP via got-scraping (no
# browser), so use the lightweight Apify Node image. Build with the REPO ROOT as
# the Docker context so the ../../../shared and ../../../shared/aux require paths
# resolve.
FROM apify/actor-node:20

WORKDIR /usr/src/app

# Copy manifest first for dependency-layer caching.
COPY --chown=myuser actors/archive-exposure/package.json ./actors/archive-exposure/package.json

RUN cd actors/archive-exposure \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

# Copy shared modules (incl. shared/aux) and this actor's source.
COPY --chown=myuser shared ./shared
COPY --chown=myuser actors/archive-exposure ./actors/archive-exposure

WORKDIR /usr/src/app/actors/archive-exposure

CMD ["node", "src/main.js"]
