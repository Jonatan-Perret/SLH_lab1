#!/usr/bin/env bash
#
# Prints the realm's RS256 signing key (kid and public key) to paste into secubank-terminal/.env.
#
# Usage:
#   keycloak/print-realm-key.sh  # Once the realm exists and after every `docker compose down -v`

set -euo pipefail

url=http://localhost:7080/realms/secubank

# Check prerequisites.
if ! command -v curl &>/dev/null; then
    echo "curl is not installed. Please install it first." >&2
    exit 1
elif ! command -v jq &>/dev/null; then
    echo "jq is not installed. Please install it first." >&2
    exit 1
fi

# Fetch the realm's public keys (JWKS) and its active RS256 public key.
if ! certs=$(curl -sf "$url/protocol/openid-connect/certs") || ! realm=$(curl -sf "$url"); then
    echo "Cannot reach $url. Start Keycloak and create the secubank realm first." >&2
    exit 1
fi

# The kid comes from the JWKS and the public key from the realm, so they only pair up if the realm
# has a single RS256 signing key.
kid=$(jq -r '[.keys[] | select(.alg == "RS256" and .use == "sig")]
    | if length == 1 then .[0].kid // empty else empty end' <<<"$certs")
key=$(jq -r '.public_key // empty' <<<"$realm")
if [ -z "$kid" ] || [ -z "$key" ]; then
    echo "The realm must have exactly one RS256 signing key. Copy it by hand from the console" \
        "(Realm settings > Keys > RS256)." >&2
    exit 1
fi

# Print the lines to paste, with the instruction as a comment so the output stays valid .env.
echo "# Replace these two lines in secubank-terminal/.env:"
echo "KEYCLOAK_REALM_KID=$kid"
echo "KEYCLOAK_REALM_PUBLIC_KEY=$key"
