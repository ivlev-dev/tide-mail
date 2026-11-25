FROM rust:bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake clang libclang-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --release -p tide-server

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data /etc/tide

COPY --from=builder /src/target/release/tide /usr/local/bin/tide

WORKDIR /data
EXPOSE 8080 2525 5870 9093
ENTRYPOINT ["tide"]
CMD ["/etc/tide/tide.toml"]
