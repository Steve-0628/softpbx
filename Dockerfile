# syntax=docker/dockerfile:1

# softpbx container image.
#
# Build (native):
#   docker build -t softpbx .
# Build (amd64 + arm64, needs buildx):
#   docker buildx build --platform linux/amd64,linux/arm64 -t softpbx .
#
# Run — SIP advertises the addresses in the config, so host networking is
# the honest way to deploy this:
#   docker run --rm --network host \
#     -v ./config.toml:/etc/softpbx/config.toml:ro \
#     -v softpbx-log:/var/lib/softpbx \
#     softpbx
# With a bridge network instead, publish the SIP and RTP ports and make the
# config advertise addresses the phones can reach. Binding SIP port 5060 on
# a bridge network additionally needs --cap-add=NET_BIND_SERVICE (the daemon
# runs as an unprivileged user), or a SIP port >= 1024 in the config.
#
# The daemon takes the config path as its first argument, defaulting to
# /etc/softpbx/config.toml. Mount your own config there; the copy baked in
# is the example from the repository, not a working site config.

# The build runs on the host architecture and cross-compiles for the target
# (the workspace is pure Rust, so only a linker per target is needed). This
# keeps arm64 images off QEMU emulation, which is painfully slow for release
# builds.
FROM --platform=$BUILDPLATFORM rust:1.98-slim-bookworm AS build

# Rust target name per Docker architecture.
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-gnu ;; \
      arm64) echo aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac > /tmp/rust-target \
 && rustup target add "$(cat /tmp/rust-target)" \
 && if [ "$TARGETARCH" = arm64 ]; then \
      apt-get update \
      && apt-get install -y --no-install-recommends \
           gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
      && rm -rf /var/lib/apt/lists/*; \
    fi

# Strip at link time (works for cross-built binaries too).
ENV CARGO_PROFILE_RELEASE_STRIP=symbols

WORKDIR /src
COPY . .

# Registry and target directories are BuildKit cache mounts, so repeated
# builds (locally, or on a warm builder) only recompile what changed.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eux; \
    target="$(cat /tmp/rust-target)"; \
    if [ "$TARGETARCH" = arm64 ]; then \
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc; \
    fi; \
    cargo build --release -p pbx-daemon --target "$target"; \
    cp "target/$target/release/pbx-daemon" /pbx-daemon

# Same Debian release as the builder, so the glibc matches what the binary
# was linked against.
FROM debian:bookworm-slim

# No packages to install: the daemon speaks plain SIP/RTP over UDP and has
# no TLS, so it needs no CA certificates either.
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin softpbx \
 && mkdir -p /etc/softpbx /var/lib/softpbx \
 && chown softpbx:softpbx /var/lib/softpbx

COPY --from=build /pbx-daemon /usr/local/bin/pbx-daemon
COPY config.toml /etc/softpbx/config.toml

# The example config's call log is a relative path ("./calls.ndjson"), so it
# ends up here — keep this directory in a volume to retain call logs.
WORKDIR /var/lib/softpbx
USER softpbx

# SIP (signaling) and the RTP relay range from the example config
# (rtp_port_base = 10000, rtp_ports = 10). All UDP.
EXPOSE 5060/udp 10000-10009/udp

ENTRYPOINT ["/usr/local/bin/pbx-daemon"]
CMD ["/etc/softpbx/config.toml"]
