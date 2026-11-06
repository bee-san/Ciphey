# Base images are pinned by digest (OpenSSF Scorecard: Pinned-Dependencies); Dependabot keeps them current.
FROM rust:1-alpine3.24@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS builder
RUN apk add --no-cache build-base pkgconfig openssl-dev
ENV PKG_CONFIG_PATH=/usr/lib/pkgconfig
ENV OPENSSL_DIR=/usr
# Encourage some layer caching here rather then copying entire directory that includes docs to builder container ~CMN
WORKDIR /app/ciphey
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY benches/ benches/
RUN cargo build --release

FROM alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a
COPY --from=builder /app/ciphey/target/release/ciphey /usr/local/bin/ciphey
ENTRYPOINT [ "/usr/local/bin/ciphey" ]
