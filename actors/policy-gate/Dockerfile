# A0 Policy Gate — no browser needed, so use the lightweight Node base image.
#
# IMPORTANT: build this image with the REPO ROOT as the Docker build context
# (the .actor/actor.json sets "dockerfile": "../Dockerfile" and on Apify the
# build context is the repo root), so that shared/ is available and the
# ../../../shared require paths in src/main.js resolve identically to local dev:
#
#   /usr/src/app/actors/policy-gate/src/main.js  ->  ../../../shared
#   ===============================================>  /usr/src/app/shared
#
FROM apify/actor-node:20

# Recreate the monorepo layout inside the image.
WORKDIR /usr/src/app

# Copy this actor's manifest first for dependency-layer caching.
COPY actors/policy-gate/package.json ./actors/policy-gate/package.json

# Install only production deps for this actor (no Playwright here).
RUN cd actors/policy-gate \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && echo "Installed dependencies:" \
 && (npm ls --omit=dev --all || true)

# Copy shared modules and this actor's source.
COPY shared ./shared
COPY actors/policy-gate ./actors/policy-gate

WORKDIR /usr/src/app/actors/policy-gate

# Standby mode is toggled in the Apify console; the image just boots main.js.
CMD ["node", "src/main.js"]
