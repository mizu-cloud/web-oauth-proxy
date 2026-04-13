const { normalizeHost } = require("./config");

function validateSiteInput(body) {
  const host = normalizeHost(body.host);
  const displayName = String(body.displayName || "").trim();
  const upstreamUrl = String(body.upstreamUrl || "").trim();
  const issuer = String(body.issuer || "").trim();
  const clientId = String(body.clientId || "").trim();
  const clientSecret = String(body.clientSecret || "").trim();
  const scopes = String(body.scopes || "openid profile email").trim();
  const redirectPath = String(body.redirectPath || "/_auth/callback").trim();
  const postLogoutRedirectUrl = String(body.postLogoutRedirectUrl || "").trim();
  const enabled = body.enabled !== false;

  if (!host) {
    throw new Error("Host is required.");
  }

  if (!displayName) {
    throw new Error("Display name is required.");
  }

  if (!upstreamUrl) {
    throw new Error("Upstream URL is required.");
  }

  if (!issuer || !clientId) {
    throw new Error("Issuer and client ID are required.");
  }

  if (body.requireClientSecret !== false && !clientSecret) {
    throw new Error("Client secret is required.");
  }

  if (!redirectPath.startsWith("/")) {
    throw new Error("Redirect path must start with '/'.");
  }

  const upstream = new URL(upstreamUrl);
  if (!["http:", "https:"].includes(upstream.protocol)) {
    throw new Error("Upstream URL must use http or https.");
  }

  if (postLogoutRedirectUrl) {
    new URL(postLogoutRedirectUrl);
  }

  return {
    host,
    displayName,
    upstreamUrl,
    enabled,
    oidc: {
      issuer,
      clientId,
      clientSecret,
      scopes,
      redirectPath,
      postLogoutRedirectUrl
    }
  };
}

module.exports = {
  validateSiteInput
};
