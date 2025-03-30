ARG SOURCE=builder
ARG IMAGE_TAG=12-slim

FROM lukemathwalker/cargo-chef:latest-rust-1 AS base

# plan dependency installation
FROM base AS planner

WORKDIR /usr/src/traefik-auth
COPY ./Cargo.toml ./Cargo.lock ./
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


# grab binary from outside (using cross)
FROM debian:${IMAGE_TAG} AS binary

COPY --chown=root:root ./dist/ /dist/
RUN mkdir -p /usr/local/cargo/bin/
RUN cp ./dist/traefik-auth-$(uname -m) /usr/local/cargo/bin/traefik-auth


# stage to grab binary based on build arg
FROM ${SOURCE} AS binary-selector

RUN cp /usr/local/cargo/bin/traefik-auth /


FROM debian:${IMAGE_TAG} AS final

ARG TARGETARCH
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY ./config/default.yml /config/
COPY --from=binary /usr/local/cargo/bin/traefik-auth /usr/local/bin/

USER 1000:999

ENTRYPOINT ["traefik-auth"]
