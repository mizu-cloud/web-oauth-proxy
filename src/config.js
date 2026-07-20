function toBoolean(value, fallback = false) {
  if (value == null) {
    return fallback;
  }

  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function resolveDatabaseUrl(env) {
  if (env.DATABASE_URL) {
    return env.DATABASE_URL;
  }

  const user = encodeURIComponent(env.MYSQL_USER || "root");
  const password = env.MYSQL_PASSWORD ? `:${encodeURIComponent(env.MYSQL_PASSWORD)}` : "";
  const host = env.MYSQL_HOST || "127.0.0.1";
  const port = env.MYSQL_PORT || "3306";
  const database = env.MYSQL_DATABASE || "web_oauth_proxy";

  return `mysql://${user}${password}@${host}:${port}/${database}`;
}

function getConfig(env = process.env) {
  return {
    port: Number(env.PORT || 3000),
    trustProxy: toBoolean(env.TRUST_PROXY, true),
    databaseUrl: resolveDatabaseUrl(env),
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
