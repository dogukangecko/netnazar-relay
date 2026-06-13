# Multi-stage: builder (rust) -> small runtime (debian-slim).
FROM rust:slim AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY netscan-proto netscan-proto
COPY netscan-relay netscan-relay
RUN cargo build --release -p netscan-relay

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/netscan-relay /usr/local/bin/netscan-relay
ENV NETSCAN_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["netscan-relay"]
