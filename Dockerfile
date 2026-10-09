# Like demidko/microservice: compile/test in a builder, ship only the runtime.
FROM rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS builder
WORKDIR /project
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY docs ./docs
COPY examples/dot-client.py ./examples/dot-client.py
COPY public ./public
COPY tests ./tests
# Optional trust bundle for development behind an enterprise TLS proxy.
# Nothing from this secret mount is copied into the image.
RUN --mount=type=secret,id=build_ca \
    if [ -f /run/secrets/build_ca ]; then export CARGO_HTTP_CAINFO=/run/secrets/build_ca; fi; \
    cargo test --locked && cargo build --locked --release --bins

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587 AS runtime
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN --mount=type=secret,id=build_ca \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
    if [ -f /run/secrets/build_ca ]; then export APT_CA_OPTION="-o Acquire::https::CaInfo=/run/secrets/build_ca"; fi; \
    apt-get ${APT_CA_OPTION:-} update && apt-get ${APT_CA_OPTION:-} install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin offtask
COPY --from=builder /project/target/release/offtask /usr/local/bin/offtask
COPY --from=builder /project/target/release/offtask-admin /usr/local/bin/offtask-admin
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/offtask
USER 10001:10001
WORKDIR /tmp
ENV OFFTASK_MODE=production NODE_ENV=production PORT=80
# No EXPOSE: App Platform routing is configured outside the Dockerfile.
ENTRYPOINT ["/usr/local/bin/offtask"]
CMD ["--production"]
