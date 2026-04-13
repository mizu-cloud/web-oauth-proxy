const path = require("path");

function toBoolean(value, fallback = false) {
  if (value == null) {
    return fallback;
  }

  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function resolveDatabasePath(databaseUrl) {
  if (!databaseUrl) {
    return path.join(process.cwd(), "data", "web-oauth-proxy.db");
  }

  if (databaseUrl.startsWith("file:")) {
    return new URL(databaseUrl).pathname;
  }

  return path.isAbsolute(databaseUrl)
    ? databaseUrl
    : path.join(process.cwd(), databaseUrl);
}

function getConfig(env = process.env) {
  return {
    port: Number(env.PORT || 3000),
    trustProxy: toBoolean(env.TRUST_PROXY, true),
    databasePath: resolveDatabasePath(env.DATABASE_URL),
    adminHost: normalizeHost(env.ADMIN_HOST || "admin.example.com"),
    adminSessionSecret: env.ADMIN_SESSION_SECRET || "change-me-admin-session-secret",
    appEncryptionKey: env.APP_ENCRYPTION_KEY || env.ADMIN_SESSION_SECRET || "change-me-app-encryption-key",
    adminOidc: {
      issuer: env.ADMIN_OIDC_ISSUER || "",
      clientId: env.ADMIN_OIDC_CLIENT_ID || "",
      clientSecret: env.ADMIN_OIDC_CLIENT_SECRET || "",
      scopes: env.ADMIN_OIDC_SCOPES || "openid profile email",
      redirectPath: env.ADMIN_OIDC_REDIRECT_PATH || "/_admin/auth/callback",
      postLogoutRedirectUrl: env.ADMIN_POST_LOGOUT_REDIRECT_URL || ""
    }
  };
}

function normalizeHost(host) {
  return String(host || "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/:\d+$/, "");
}

module.exports = {
  getConfig,
  normalizeHost
};
