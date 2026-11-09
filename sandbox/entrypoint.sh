#!/bin/sh
# Plant canary credentials where an attacker would look for real ones, then hand over.
set -eu

mkdir -p "$HOME/.aws"
printf '[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n' \
  "${AWS_ACCESS_KEY_ID:-}" "${AWS_SECRET_ACCESS_KEY:-}" > "$HOME/.aws/credentials"

exec "$@"
