# AUX Email-Auth Posture — no browser needed (pure HTTP DNS-over-HTTPS via
# got-scraping), so use the lightweight Apify Node image. Build with REPO ROOT
# as the Docker context so the ../../../shared and ../../../shared/aux require
# paths resolve.
FROM apify/actor-node:20

WORKDIR /usr/src/app

# Copy manifest first for dependency-layer caching.
COPY --chown=myuser actors/email-auth-posture/package.json ./actors/email-auth-posture/package.json

RUN cd actors/email-auth-posture \
 && npm --quiet set progress=false \
 && npm install --omit=dev --no-optional \
 && (npm ls --omit=dev --all || true)

# Copy shared modules (incl. shared/aux) and this actor's source.
COPY --chown=myuser shared ./shared
COPY --chown=myuser actors/email-auth-posture ./actors/email-auth-posture

WORKDIR /usr/src/app/actors/email-auth-posture

CMD ["node", "src/main.js"]
