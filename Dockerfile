FROM tailscale/tailscale@sha256:c507f3a2a6ab1cabd8d809b98edeb41edbd5c3fb6ad9632ffd098b4c7d0b4065 AS tailscale
FROM alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates iproute2 nftables python3 wireguard-tools-wg

COPY --from=tailscale /usr/local/bin/tailscale /usr/local/bin/tailscale
COPY --from=tailscale /usr/local/bin/tailscaled /usr/local/bin/tailscaled
COPY router_runtime.py /usr/local/bin/router-runtime
COPY router.nft /usr/local/share/vprouter/router.nft

RUN chmod 0755 /usr/local/bin/router-runtime

HEALTHCHECK --interval=20s --timeout=5s --retries=3 \
    CMD /usr/local/bin/router-runtime --status
ENTRYPOINT ["/usr/local/bin/router-runtime"]
