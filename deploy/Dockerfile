FROM rust:1.82-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release \
    -p aisoc-agent \
    -p aisoc-ingest \
    -p aisoc-api \
    -p aisoc-console \
    -p aisoc-web-guard \
    -p aisoc-storage

FROM debian:bookworm-slim AS runtime
ENV AISOC_ENVIRONMENT=production \
    AISOC_LOG=info
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 aisoc \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin aisoc \
    && install -d -m 0700 -o aisoc -g aisoc /var/lib/aisoc /var/lib/aisoc-ingest
COPY --from=builder /build/target/release/aisoc-agent /usr/local/bin/aisoc-agent
COPY --from=builder /build/target/release/aisoc-ingest /usr/local/bin/aisoc-ingest
COPY --from=builder /build/target/release/aisoc-api /usr/local/bin/aisoc-api
COPY --from=builder /build/target/release/aisoc-console /usr/local/bin/aisoc-console
COPY --from=builder /build/target/release/aisoc-web-guard /usr/local/bin/aisoc-web-guard
COPY --from=builder /build/target/release/aisoc-db /usr/local/bin/aisoc-db
USER 10001:10001
STOPSIGNAL SIGTERM
EXPOSE 8000 8080 8088
CMD ["/usr/local/bin/aisoc-api"]
