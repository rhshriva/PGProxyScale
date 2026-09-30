# Optional real CPU instrumentation fixture, isolated from the developer host.
FROM postgres:17-bookworm
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends postgresql-17-pg-stat-kcache \
 && rm -rf /var/lib/apt/lists/*
