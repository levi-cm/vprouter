#!/bin/bash

echo "Starting tailscaled"

if [ "$VPR_DEBUG" = "true" ]; then
    tailscaled &
else
    tailscaled >/dev/null 2>&1 &
fi

sleep 5
tailscale set --auto-update || true

if [ -n "$TS_AUTHKEY" ]; then
    tailscale up --authkey="$TS_AUTHKEY" --advertise-exit-node --hostname="${TS_HOSTNAME:-vprouter}" --accept-dns=false
else
    echo "TS_AUTHKEY is not set; starting interactive Tailscale login"
    tailscale up --advertise-exit-node --hostname="${TS_HOSTNAME:-vprouter}" --accept-dns=false
fi

echo "Waiting for tailscale status"

until tailscale status >/dev/null 2>&1
do
  sleep 1
done

echo "Tailscale connected"

if [ -z "$WIREGUARD_PRIVATEKEY" ]; then
    echo "WIREGUARD_PRIVATEKEY is not set"
    exit 1
fi

if [ -z "$WIREGUARD_ADDRESS" ]; then
    echo "WIREGUARD_ADDRESS is not set"
    exit 1
fi

if [ -z "$WIREGUARD_ENDPOINT" ]; then
    echo "WIREGUARD_ENDPOINT is not set"
    exit 1
fi

if [ -z "$WIREGUARD_PEERKEY" ]; then
    echo "WIREGUARD_PEERKEY is not set"
    exit 1
fi

mkdir -p /etc/wireguard
cat <<EOF > /etc/wireguard/wireguard.conf
[Interface]
PrivateKey = $WIREGUARD_PRIVATEKEY

[Peer]
PublicKey = $WIREGUARD_PEERKEY
AllowedIPs = ${WIREGUARD_ALLOWEDIPS:-0.0.0.0/0}
Endpoint = $WIREGUARD_ENDPOINT
EOF

echo "Setting up WireGuard"

ip link add wg0 type wireguard
wg setconf wg0 /etc/wireguard/wireguard.conf
ip addr add "$WIREGUARD_ADDRESS" dev wg0
ip link set wg0 up

DEFAULT_GATEWAY=$(ip route | awk '/default/ {print $3}')
DEFAULT_DEVICE=$(ip route | awk '/default/ {print $5}')

echo "Adding WireGuard route"

ip route add "${WIREGUARD_ENDPOINT%:*}" via "$DEFAULT_GATEWAY" dev "$DEFAULT_DEVICE"
ip route add "${DNS}/32" dev wg0
ip route add 100.64.0.0/10 dev tailscale0
ip route replace default dev wg0

echo "Setting up WireGuard firewall"

iptables -N vprouter-forward
iptables -I FORWARD -j vprouter-forward
iptables -A vprouter-forward -m comment --comment "Allow return traffic from WireGuard to Tailscale" -j ACCEPT -m conntrack --ctstate ESTABLISHED,RELATED -i wg0 -o tailscale0
iptables -A vprouter-forward -m comment --comment "Allow Tailscale traffic to WireGuard" -i tailscale0 -o wg0 -j ACCEPT
iptables -A vprouter-forward -m comment --comment "Drop unestablished traffic from WireGuard to Tailscale" -j DROP -i wg0 -o tailscale0

iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE -m comment --comment "Masquerade WireGuard traffic"

echo "WireGuard setup complete"
echo "Setting up split DNS"

TAILNET_DOMAIN=$(tailscale status --json | jq -r '.MagicDNSSuffix')

echo "Current tailnet domain: $TAILNET_DOMAIN"

if [ -z "$TAILNET_DOMAIN" ]; then
  echo "Tailnet domain was not detected"
  exit 1
fi

if [ -z "$DNS" ]; then
  echo "DNS not set"
  exit 1
fi

cat <<EOF > /etc/dnsmasq.conf
no-resolv
listen-address=127.0.0.1
bind-interfaces
server=/${TAILNET_DOMAIN}/100.100.100.100
server=${DNS}
EOF

if [ "$VPR_DEBUG" = "true" ]; then
    dnsmasq &
else
    dnsmasq >/dev/null 2>&1 &
fi

cat <<EOF > /etc/resolv.conf
nameserver 127.0.0.1
EOF

iptables -N vprouter-dns

iptables -A vprouter-dns -o tailscale0 -p udp --dport 53 -m comment --comment "Allow Tailscale DNS traffic" -j ACCEPT
iptables -A vprouter-dns -o tailscale0 -p tcp --dport 53 -m comment --comment "Allow Tailscale DNS traffic" -j ACCEPT
iptables -A vprouter-dns -o wg0 -p udp --dport 53 -m comment --comment "Allow WireGuard DNS traffic" -j ACCEPT
iptables -A vprouter-dns -o wg0 -p tcp --dport 53 -m comment --comment "Allow WireGuard DNS traffic" -j ACCEPT
iptables -A vprouter-dns -o "$DEFAULT_DEVICE" -p udp --dport 53 -m comment --comment "Drop default DNS traffic" -j DROP
iptables -A vprouter-dns -o "$DEFAULT_DEVICE" -p tcp --dport 53 -m comment --comment "Drop default DNS traffic" -j DROP
iptables -A vprouter-dns -o "$DEFAULT_DEVICE" -p tcp --dport 853 -m comment --comment "Drop DNS over TLS traffic" -j DROP
iptables -A vprouter-dns -j RETURN

iptables -I OUTPUT -j vprouter-dns -m comment --comment "Manage DNS traffic"

echo "Split DNS setup complete"

wait
