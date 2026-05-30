# AUX GitHub Leak Scan — pure HTTP via got-scraping (no browser), so use the
# lightweight Apify Node image. Build with the REPO ROOT as the Docker context so
# the ../../../shared and ../../../shared/aux require paths resolve.
FROM apify/actor-node:20

WORKDIR /usr/src/app

# Copy manifest first for dependency-layer caching.
COPY --chown=myuser actors/gh-leak-scan/package.json ./actors/gh-leak-scan/package.json

RUN cd actors/gh-leak-scan \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

# Copy shared modules (incl. shared/aux) and this actor's source.
COPY --chown=myuser shared ./shared
COPY --chown=myuser actors/gh-leak-scan ./actors/gh-leak-scan

WORKDIR /usr/src/app/actors/gh-leak-scan

CMD ["node", "src/main.js"]
