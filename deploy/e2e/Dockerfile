# Test node for the Yggdrasil e2e: Yggdrasil + the tools the script and daemon need.
FROM debian:bookworm-slim
ARG YGG_VERSION=0.5.15
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl iproute2 iputils-ping jq nftables netcat-openbsd procps python3 \
 && curl -fsSL -o /tmp/ygg.deb "https://github.com/yggdrasil-network/yggdrasil-go/releases/download/v${YGG_VERSION}/yggdrasil-${YGG_VERSION}-amd64.deb" \
 && (dpkg -i /tmp/ygg.deb || apt-get install -f -y --no-install-recommends) \
 && rm -rf /var/lib/apt/lists/* /tmp/ygg.deb
