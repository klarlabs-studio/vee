# Vee in a container, for CI runners.
#
#   docker build .                   builds Vee from this checkout
#   docker build --target release .  packages prebuilt binaries from
#                                    dist/<amd64|arm64>/vee (the release workflow)
#
# The image holds Vee and Git. It suits API providers; reviewers that use an
# agent CLI need that CLI installed in a derived image.

# The web UI is prebuilt in web/dist and compiled into the binary, so only Rust
# is needed to build from source.
FROM rust:1-bookworm AS source-build
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin vee

# Vee runs Git at runtime; certificates are needed for hosting and provider APIs.
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --yes --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 vee \
    # CI checkouts are owned by another user, and CI may run the container as
    # another user, so this is system configuration rather than the vee user's.
    && git config --system --add safe.directory '*'
WORKDIR /work
ENTRYPOINT ["vee"]

FROM runtime AS release
ARG TARGETARCH
COPY dist/${TARGETARCH}/vee /usr/local/bin/vee
USER vee

FROM runtime
COPY --from=source-build /src/target/release/vee /usr/local/bin/vee
USER vee
