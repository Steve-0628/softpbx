FROM rust:1.98-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p pbx-daemon

FROM debian:bookworm-slim
COPY --from=build /src/target/release/pbx-daemon /usr/local/bin/pbx-daemon

WORKDIR /var/lib/softpbx

EXPOSE 5060/udp 10000-10009/udp

ENTRYPOINT ["pbx-daemon"]
CMD ["/etc/softpbx/config.toml"]
