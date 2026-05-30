# AUX Metadata-Exposure — pure HTTP fetch + local EXIF/PDF parse (no browser),
# so use the lightweight Apify Node image. Build with the REPO ROOT as the Docker
# context so the ../../../shared and ../../../shared/aux require paths resolve.
FROM apify/actor-node:20

WORKDIR /usr/src/app

# Copy manifest first for dependency-layer caching.
COPY --chown=myuser actors/metadata-exposure/package.json ./actors/metadata-exposure/package.json

RUN cd actors/metadata-exposure \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

# Copy shared modules (incl. shared/aux) and this actor's source.
COPY --chown=myuser shared ./shared
COPY --chown=myuser actors/metadata-exposure ./actors/metadata-exposure

WORKDIR /usr/src/app/actors/metadata-exposure

CMD ["node", "src/main.js"]
