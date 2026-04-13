const crypto = require("crypto");

function deriveKey(secret) {
  return crypto.createHash("sha256").update(String(secret)).digest();
}

function encryptSecret(plaintext, secret) {
  if (!plaintext) {
    return "";
  }

  const iv = crypto.randomBytes(12);
  const key = deriveKey(secret);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64");
}

function decryptSecret(payload, secret) {
  if (!payload) {
    return "";
  }

  const data = Buffer.from(payload, "base64");
  const iv = data.subarray(0, 12);
  const tag = data.subarray(12, 28);
  const encrypted = data.subarray(28);
  const key = deriveKey(secret);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
}

function hostCookieName(prefix, host) {
  const digest = crypto.createHash("sha256").update(String(host)).digest("hex").slice(0, 12);
  return `${prefix}_${digest}`;
}

module.exports = {
  encryptSecret,
  decryptSecret,
  hostCookieName
};
