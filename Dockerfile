ARG DOCKER_ALPINE_VERSION=3.23
FROM rust:alpine${DOCKER_ALPINE_VERSION} AS builder

RUN apk add --no-cache musl-dev make bash

WORKDIR /pcrypt

COPY src src
COPY Cargo.toml .
COPY Cargo.lock .
COPY Makefile .

RUN make release


ARG DOCKER_ALPINE_VERSION=3.23
FROM alpine:${DOCKER_ALPINE_VERSION}
ARG PCRYPT_VERSION
LABEL org.opencontainers.image.title="pcrypt"
LABEL org.opencontainers.image.description="Archive (zip) + Encrypt (AES-256) + Compress (Zstd) directory files"
LABEL org.opencontainers.image.version="${PCRYPT_VERSION}"

WORKDIR /
COPY --from=builder /pcrypt/build/pcrypt-* /usr/local/bin/pcrypt

ENTRYPOINT ["/usr/local/bin/pcrypt"]
CMD ["--help"]
