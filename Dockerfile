ARG SOURCE=builder

FROM clux/muslrust:stable AS base
USER root
RUN cargo install cargo-chef

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
RUN cargo chef cook --release --target $(uname -m)-unknown-linux-musl --recipe-path recipe.json

COPY ./Cargo.toml ./Cargo.lock ./
COPY ./src ./src
RUN cargo install --target $(uname -m)-unknown-linux-musl --path . && \
    mv /opt/cargo/bin/traefik-auth /usr/local/bin/traefik-auth


# grab binary from outside (using cross)
FROM alpine AS binary

COPY --chown=root:root ./dist/ /dist/
RUN mkdir -p /usr/local/bin/
RUN cp ./dist/traefik-auth-$(uname -m) /usr/local/bin/traefik-auth


# stage to grab binary based on build arg
FROM ${SOURCE} AS binary-selector

RUN cp /usr/local/bin/traefik-auth /


FROM gcr.io/distroless/static AS final

COPY ./config/default.yml /config/
COPY --from=binary-selector /traefik-auth /usr/local/bin/

USER 1000:999

ENTRYPOINT ["traefik-auth"]
