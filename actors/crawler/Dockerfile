# A3 Crawler — needs Playwright + Chromium, so use Apify's Playwright image.
# Build with REPO ROOT as the Docker context so shared/ resolves through the
# ../../../shared require paths.
FROM apify/actor-node-playwright-chrome:20

WORKDIR /usr/src/app

# Copy manifest first for dependency-layer caching.
COPY --chown=myuser actors/crawler/package.json ./actors/crawler/package.json

RUN cd actors/crawler \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

# Copy shared modules and this actor's source (keep ownership for the non-root user).
COPY --chown=myuser shared ./shared
COPY --chown=myuser actors/crawler ./actors/crawler

WORKDIR /usr/src/app/actors/crawler

CMD ["node", "src/main.js"]
