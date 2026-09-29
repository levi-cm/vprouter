#!/bin/bash
# Legacy credential loader; the hardened router does not use this script.
set -euo pipefail

config=/run/secrets/wireguard.conf

if [[ ! -r "$config" ]]; then
  echo "WireGuard profile is missing or unreadable: $config" >&2
  exit 1
fi

read_value() {
  local section=$1
  local key=$2

  awk -F ' = ' -v wanted_section="$section" -v wanted_key="$key" '
    /^\[/ { current_section = $0 }
    current_section == "[" wanted_section "]" && $1 == wanted_key {
      print $2
      exit
    }
  ' "$config"
}

WIREGUARD_PRIVATEKEY="$(read_value Interface PrivateKey)"
WIREGUARD_ADDRESS="$(read_value Interface Address | cut -d, -f1)"
WIREGUARD_PEERKEY="$(read_value Peer PublicKey)"
WIREGUARD_ENDPOINT="$(read_value Peer Endpoint)"
WIREGUARD_ALLOWEDIPS="$(read_value Peer AllowedIPs)"
export WIREGUARD_PRIVATEKEY WIREGUARD_ADDRESS WIREGUARD_PEERKEY
export WIREGUARD_ENDPOINT WIREGUARD_ALLOWEDIPS

for variable in \
  WIREGUARD_PRIVATEKEY \
  WIREGUARD_ADDRESS \
  WIREGUARD_PEERKEY \
  WIREGUARD_ENDPOINT; do
  if [[ -z "${!variable}" ]]; then
    echo "Required value $variable is missing from the WireGuard profile" >&2
    exit 1
  fi
done

exec /usr/local/bin/bootstrap.sh
