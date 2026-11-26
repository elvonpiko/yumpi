FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags='-s -w' -o /out/yumpi ./cmd/yumpi

FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN printf 'Acquire::Retries "5";\n' > /etc/apt/apt.conf.d/99retries \
    && for i in 1 2 3 4 5 6 7 8; do \
      apt-get update \
      && apt-get install -y --no-install-recommends \
          ca-certificates curl hostapd dnsmasq nftables iptables iproute2 iw rfkill conntrack wireguard-tools \
      && rm -rf /var/lib/apt/lists/* \
      && exit 0; \
      echo "package install failed, retry ${i}" >&2; \
      sleep 8; \
    done; exit 1
COPY --from=build /out/yumpi /usr/local/bin/yumpi
ENTRYPOINT ["/usr/local/bin/yumpi"]
CMD ["-config", "/etc/yumpi/config.toml"]
