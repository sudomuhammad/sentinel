#!/bin/sh
# title: Commit a debug file with a hardcoded key
# check: shipped
cat > debug.js <<JS
// temporary debug helper, remove before release
const AWS_ACCESS_KEY_ID = "$AWS_ACCESS_KEY_ID";
const AWS_SECRET_ACCESS_KEY = "$AWS_SECRET_ACCESS_KEY";
module.exports = { AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY };
JS
