#!/usr/bin/env node

const tls = require("tls");
const crypto = require("crypto");

const DEFAULT_PORT = 443;

function usage() {
  console.log("Usage: node certpeek.js <domain> [port]");
}

function formatObject(obj) {
  if (!obj) return "N/A";
  return Object.entries(obj)
    .map(([k, v]) => `${k}=${v}`)
    .join(", ");
}

function daysLeft(validTo) {
  const now = Date.now();
  const expiry = new Date(validTo).getTime();
  return Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
}

function expiryStatus(days) {
  if (days < 0) return "Expired";
  if (days <= 30) return "Expiring soon";
  return "Healthy";
}

function sha256Fingerprint(raw) {
  return crypto
    .createHash("sha256")
    .update(raw)
    .digest("hex")
    .toUpperCase()
    .match(/.{1,2}/g)
    .join(":");
}

function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    usage();
    process.exit(1);
  }

  const host = args[0];
  const port = args[1] ? Number(args[1]) : DEFAULT_PORT;

  if (Number.isNaN(port)) {
    console.error("Port must be a number.");
    process.exit(1);
  }

  const socket = tls.connect(
    {
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
      timeout: 10000,
    },
    () => {
      const cert = socket.getPeerCertificate(true);

      if (!cert || Object.keys(cert).length === 0) {
        console.error("No certificate received.");
        socket.end();
        process.exit(1);
      }

      const left = daysLeft(cert.valid_to);
      const fingerprint = cert.raw
        ? sha256Fingerprint(cert.raw)
        : "N/A";

      console.log(`Host: ${host}`);
      console.log(`Port: ${port}`);
      console.log();

      console.log("TLS");
      console.log("---");
      console.log(`Authorized : ${socket.authorized}`);
      console.log(`TLS Version: ${socket.getProtocol() || "N/A"}`);
      console.log(`Auth Error : ${socket.authorizationError || "None"}`);

      console.log();
      console.log("Certificate Info");
      console.log("----------------");
      console.log(`Subject            : ${formatObject(cert.subject)}`);
      console.log(`Issuer             : ${formatObject(cert.issuer)}`);
      console.log(`Valid From         : ${cert.valid_from || "N/A"}`);
      console.log(`Valid Until        : ${cert.valid_to || "N/A"}`);
      console.log(`Days Left          : ${left}`);
      console.log(`Expiry Status      : ${expiryStatus(left)}`);
      console.log(`Serial Number      : ${cert.serialNumber || "N/A"}`);
      console.log(`SHA256 Fingerprint : ${fingerprint}`);

      console.log();
      console.log("SAN Names");
      console.log("---------");

      if (cert.subjectaltname) {
        cert.subjectaltname
          .split(",")
          .map((v) => v.trim())
          .forEach((v) => console.log(v));
      } else {
        console.log("None");
      }

      socket.end();
    }
  );

  socket.on("error", (err) => {
    console.error("Connection error:", err.message);
    process.exit(1);
  });

  socket.on("timeout", () => {
    console.error("Connection timed out.");
    socket.destroy();
    process.exit(1);
  });
}

main();
