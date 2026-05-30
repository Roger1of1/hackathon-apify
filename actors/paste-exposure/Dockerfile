# AUX Paste-Exposure — no browser needed (pure HTTP via got-scraping), so use the
# lightweight Apify Node image. Build with REPO ROOT as the Docker context so the
# ../../../shared and ../../../shared/aux require paths resolve.
FROM apify/actor-node:20

WORKDIR /usr/src/app

# Copy manifest first for dependency-layer caching.
COPY --chown=myuser actors/paste-exposure/package.json ./actors/paste-exposure/package.json

RUN cd actors/paste-exposure \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

# Copy shared modules (incl. shared/aux) and this actor's source.
COPY --chown=myuser shared ./shared
COPY --chown=myuser actors/paste-exposure ./actors/paste-exposure

WORKDIR /usr/src/app/actors/paste-exposure

CMD ["node", "src/main.js"]
