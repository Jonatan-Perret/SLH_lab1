#!/usr/bin/env bash
#
# Exports the secubank realm with its users to keycloak/realm/, without the realm keys.
#
# Usage:
#   keycloak/export-realm.sh  # Export the realm (Keycloak is stopped during the export)

set -euo pipefail
cd "$(dirname "$0")/.."

# Check prerequisites.
if ! command -v docker &>/dev/null; then
    echo "docker is not installed. Please install it first." >&2
    exit 1
elif ! command -v jq &>/dev/null; then
    echo "jq is not installed. Please install it first." >&2
    exit 1
elif [ ! -f keycloak/.env ]; then
    echo "keycloak/.env not found. Please create it from keycloak/.env.example first." >&2
    exit 1
fi

file=keycloak/realm/secubank-realm.json

# Prompt the user for confirmation before overwriting a previous export.
if [ -f "$file" ]; then
    read -rp "This overwrites $file and stops Keycloak during the export. Continue? (y/N) " answer
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        echo "Aborting." >&2
        exit 1
    fi
fi

# Stop Keycloak so that the export command has its database to itself, and start it again on exit.
docker compose stop
trap 'docker compose up -d --wait' EXIT

# Export the realm with its users, then remove the realm keys (private keys and certificates).
docker compose run --rm --no-deps -v ./keycloak/realm:/export:z keycloak \
    export --db dev-file --realm secubank --dir /export --users realm_file
jq 'del(.components["org.keycloak.keys.KeyProvider"])' "$file" >"$file.tmp"
mv "$file.tmp" "$file"
