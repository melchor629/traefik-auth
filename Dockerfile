FROM lukemathwalker/cargo-chef:latest-rust-1 AS base

# plan dependency installation
FROM base AS planner

WORKDIR /usr/src/traefik-auth
COPY ./Cargo.toml ./Cargo.lock .
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo chef prepare --recipe-path recipe.json


# install dependencies in a layer
FROM base AS builder

WORKDIR /usr/src/traefik-auth
COPY --from=planner /usr/src/traefik-auth/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY ./Cargo.toml ./Cargo.lock ./
COPY ./src ./src
RUN cargo install --path .


FROM debian:11-slim AS final

RUN apt-get update && \
    apt-get install -y libssl1.1 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY ./config/default.yml /config/
COPY --from=builder /usr/local/cargo/bin/traefik-auth /usr/local/bin/

ENTRYPOINT ["traefik-auth"]