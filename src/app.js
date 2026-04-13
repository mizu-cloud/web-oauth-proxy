const path = require("path");
const express = require("express");
const session = require("express-session");
const { createProxyMiddleware } = require("http-proxy-middleware");
const { getConfig, normalizeHost } = require("./config");
const { createDatabase } = require("./db");
const { hostCookieName } = require("./crypto");
const { OidcService } = require("./oidc");
const { validateSiteInput } = require("./validation");

function createApp(options = {}) {
  const config = options.config || getConfig();
  const repository =
    options.repository || createDatabase(config.databasePath, config.appEncryptionKey);
  const oidcService = options.oidcService || new OidcService();
  const app = express();

  if (config.trustProxy) {
    app.set("trust proxy", 1);
  }

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  const MemoryStore = session.MemoryStore;
  const sharedStore = new MemoryStore();
  const sessionMiddlewareCache = new Map();
  const proxyMiddlewareCache = new Map();

  function getSessionMiddleware(cookieName) {
    if (!sessionMiddlewareCache.has(cookieName)) {
      sessionMiddlewareCache.set(
        cookieName,
        session({
          store: sharedStore,
          secret: config.adminSessionSecret,
          resave: false,
          saveUninitialized: false,
          cookie: {
            httpOnly: true,
            secure: "auto",
            sameSite: "lax"
          },
          name: cookieName
        })
      );
    }

    return sessionMiddlewareCache.get(cookieName);
  }

  function resolveHost(req) {
    const forwardedHost = req.headers["x-forwarded-host"];
    const source = Array.isArray(forwardedHost) ? forwardedHost[0] : forwardedHost || req.headers.host;
    return normalizeHost(String(source || ""));
  }

  function resolveProto(req) {
    const forwardedProto = req.headers["x-forwarded-proto"];
    if (typeof forwardedProto === "string" && forwardedProto.length > 0) {
      return forwardedProto.split(",")[0].trim();
    }

    return req.protocol || "http";
  }

  function buildAbsoluteUrl(req, host, relativePath) {
    return `${resolveProto(req)}://${host}${relativePath}`;
  }

  function ensureAdminHost(req, res, next) {
    if (resolveHost(req) !== config.adminHost) {
      return res
        .status(404)
        .type("text/html")
        .send(renderErrorPage("Admin host only", "This host does not serve the admin UI."));
    }
    return next();
  }

  function applyDynamicSession(prefix, hostResolver) {
    return (req, res, next) => {
      const cookieName = hostCookieName(prefix, hostResolver(req));
      return getSessionMiddleware(cookieName)(req, res, next);
    };
  }

  const adminRouter = express.Router();
  adminRouter.use(ensureAdminHost);
  adminRouter.use(applyDynamicSession("admin_session", () => config.adminHost));

  adminRouter.get("/_admin/auth/login", async (req, res) => {
    try {
      const redirectUri = buildAbsoluteUrl(req, config.adminHost, config.adminOidc.redirectPath);
      const client = await oidcService.buildClient(
        {
          issuer: config.adminOidc.issuer,
          clientId: config.adminOidc.clientId,
          clientSecret: config.adminOidc.clientSecret
        },
        redirectUri
      );
      const state = oidcService.generateState();
      const nonce = oidcService.generateNonce();
      req.session.oidc = {
        state,
        nonce,
        returnTo: "/"
      };

      res.redirect(
        oidcService.buildAuthorizationUrl(client, redirectUri, config.adminOidc.scopes, state, nonce)
      );
    } catch (error) {
      res.status(500).type("text/html").send(renderErrorPage("Admin login failed", sanitizeError(error)));
    }
  });

  adminRouter.get(config.adminOidc.redirectPath, async (req, res) => {
    try {
      const redirectUri = buildAbsoluteUrl(req, config.adminHost, config.adminOidc.redirectPath);
      const client = await oidcService.buildClient(
        {
          issuer: config.adminOidc.issuer,
          clientId: config.adminOidc.clientId,
          clientSecret: config.adminOidc.clientSecret
        },
        redirectUri
      );
      const tokenSet = await oidcService.callback(client, redirectUri, client.callbackParams(req), {
        state: req.session.oidc?.state,
        nonce: req.session.oidc?.nonce
      });

      const userinfo = tokenSet.claims();
      req.session.adminUser = {
        sub: userinfo.sub,
        email: userinfo.email || "",
        name: userinfo.name || userinfo.preferred_username || userinfo.email || userinfo.sub
      };
      res.redirect(req.session.oidc?.returnTo || "/");
    } catch (error) {
      res
        .status(401)
        .type("text/html")
        .send(renderErrorPage("Admin callback failed", sanitizeError(error)));
    }
  });

  adminRouter.post("/_admin/auth/logout", (req, res) => {
    req.session.destroy(() => {
      res.redirect(config.adminOidc.postLogoutRedirectUrl || "/");
    });
  });

  adminRouter.use((req, res, next) => {
    if (req.path.startsWith("/_admin/auth/")) {
      return next();
    }

    if (!req.session.adminUser) {
      return res.redirect("/_admin/auth/login");
    }

    return next();
  });

  adminRouter.get("/api/me", (req, res) => {
    res.json({ user: req.session.adminUser });
  });

  adminRouter.get("/api/sites", (req, res) => {
    res.json({
      sites: repository.listSites().map(toPublicSite)
    });
  });

  adminRouter.post("/api/sites", async (req, res) => {
    try {
      const input = validateSiteInput(req.body);
      await oidcService.validateConfiguration(input.oidc);
      const site = repository.createSite(input);
      res.status(201).json({ site: toPublicSite(site) });
    } catch (error) {
      res.status(400).json({ error: sanitizeError(error) });
    }
  });

  adminRouter.put("/api/sites/:id", async (req, res) => {
    try {
      const existing = repository.getSiteById(Number(req.params.id));
      if (!existing) {
        return res.status(404).json({ error: "Site not found." });
      }

      const input = validateSiteInput({
        ...req.body,
        requireClientSecret: Boolean(req.body.clientSecret)
      });
      if (!input.oidc.clientSecret) {
        input.oidc.clientSecret = existing.oidc.clientSecret;
      }
      await oidcService.validateConfiguration(input.oidc);
      const site = repository.updateSite(existing.id, input);
      return res.json({ site: toPublicSite(site) });
    } catch (error) {
      return res.status(400).json({ error: sanitizeError(error) });
    }
  });

  adminRouter.delete("/api/sites/:id", (req, res) => {
    const existing = repository.getSiteById(Number(req.params.id));
    if (!existing) {
      return res.status(404).json({ error: "Site not found." });
    }

    repository.deleteSite(existing.id);
    res.status(204).end();
  });

  adminRouter.post("/api/sites/:id/toggle", (req, res) => {
    const existing = repository.getSiteById(Number(req.params.id));
    if (!existing) {
      return res.status(404).json({ error: "Site not found." });
    }

    const site = repository.updateSite(existing.id, {
      ...existing,
      enabled: !existing.enabled
    });
    res.json({ site: toPublicSite(site) });
  });

  adminRouter.use(express.static(path.join(process.cwd(), "public")));
  adminRouter.get("*", (req, res) => {
    res.sendFile(path.join(process.cwd(), "public", "index.html"));
  });

  const siteRouter = express.Router();
  siteRouter.use(applyDynamicSession("site_session", (req) => resolveHost(req)));

  async function handleSiteLogin(req, res) {
    const host = resolveHost(req);
    const site = repository.getSiteByHost(host);
    if (!site || !site.enabled) {
      return res
        .status(404)
        .type("text/html")
        .send(renderErrorPage("Unknown host", `No active site is configured for ${host}.`));
    }

    try {
      const redirectUri = buildAbsoluteUrl(req, site.host, site.oidc.redirectPath);
      const client = await oidcService.buildClient(site.oidc, redirectUri);
      const state = oidcService.generateState();
      const nonce = oidcService.generateNonce();
      req.session.siteAuth = {
        state,
        nonce,
        returnTo: req.query.returnTo || "/",
        host
      };

      res.redirect(oidcService.buildAuthorizationUrl(client, redirectUri, site.oidc.scopes, state, nonce));
    } catch (error) {
      res.status(500).type("text/html").send(renderErrorPage("OIDC login failed", sanitizeError(error)));
    }
  }

  async function handleSiteCallback(req, res) {
    const host = resolveHost(req);
    const site = repository.getSiteByHost(host);
    if (!site || !site.enabled) {
      return res
        .status(404)
        .type("text/html")
        .send(renderErrorPage("Unknown host", `No active site is configured for ${host}.`));
    }

    try {
      const redirectUri = buildAbsoluteUrl(req, site.host, site.oidc.redirectPath);
      const client = await oidcService.buildClient(site.oidc, redirectUri);
      const tokenSet = await oidcService.callback(client, redirectUri, client.callbackParams(req), {
        state: req.session.siteAuth?.state,
        nonce: req.session.siteAuth?.nonce
      });

      const claims = tokenSet.claims();
      req.session.user = {
        host,
        sub: claims.sub,
        email: claims.email || "",
        name: claims.name || claims.preferred_username || claims.email || claims.sub
      };
      res.redirect(req.session.siteAuth?.returnTo || "/");
    } catch (error) {
      res
        .status(401)
        .type("text/html")
        .send(renderErrorPage("OIDC callback failed", sanitizeError(error)));
    }
  }

  siteRouter.get("/_auth/login", handleSiteLogin);
  siteRouter.get("/_auth/callback", handleSiteCallback);
  siteRouter.get("*", (req, res, next) => {
    const site = repository.getSiteByHost(resolveHost(req));
    if (site && req.path === site.oidc.redirectPath && site.oidc.redirectPath !== "/_auth/callback") {
      return handleSiteCallback(req, res);
    }

    return next();
  });

  siteRouter.post("/_auth/logout", (req, res) => {
    const host = resolveHost(req);
    const site = repository.getSiteByHost(host);
    const redirectTarget = site?.oidc.postLogoutRedirectUrl || "/";
    req.session.destroy(() => {
      res.redirect(redirectTarget);
    });
  });

  siteRouter.use(async (req, res, next) => {
    const host = resolveHost(req);
    const site = repository.getSiteByHost(host);

    if (!site) {
      return res
        .status(404)
        .type("text/html")
        .send(renderErrorPage("Unknown host", `No site is configured for host ${host}.`));
    }

    if (!site.enabled) {
      return res
        .status(503)
        .type("text/html")
        .send(renderErrorPage("Site disabled", `${host} is currently disabled.`));
    }

    if (!req.session.user || req.session.user.host !== host) {
      return res.redirect(`/_auth/login?returnTo=${encodeURIComponent(req.originalUrl)}`);
    }

    req.site = site;
    return next();
  });

  siteRouter.use((req, res, next) => {
    const target = req.site.upstreamUrl;
    if (!proxyMiddlewareCache.has(target)) {
      proxyMiddlewareCache.set(
        target,
        createProxyMiddleware({
          target,
          changeOrigin: true,
          xfwd: true,
          ws: true,
          proxyTimeout: 15000,
          onProxyReq(proxyReq, clientReq) {
            proxyReq.setHeader("X-Authenticated-User", clientReq.session.user.name);
            proxyReq.setHeader("X-Authenticated-Email", clientReq.session.user.email || "");
            proxyReq.setHeader("X-Authenticated-Sub", clientReq.session.user.sub);
          },
          onError(error, _req, proxyRes) {
            if (!proxyRes.headersSent) {
              proxyRes.writeHead(502, { "Content-Type": "text/html; charset=utf-8" });
            }
            proxyRes.end(renderErrorPage("Upstream unavailable", sanitizeError(error)));
          }
        })
      );
    }

    return proxyMiddlewareCache.get(target)(req, res, next);
  });

  app.use((req, res, next) => {
    if (resolveHost(req) === config.adminHost) {
      return adminRouter(req, res, next);
    }

    return siteRouter(req, res, next);
  });

  app.use((error, req, res, _next) => {
    console.error("request_error", {
      host: resolveHost(req),
      path: req.path,
      message: sanitizeError(error)
    });
    res.status(500).type("text/html").send(renderErrorPage("Unexpected error", sanitizeError(error)));
  });

  return {
    app,
    repository,
    oidcService,
    config
  };
}

function sanitizeError(error) {
  return error instanceof Error ? error.message : String(error);
}

function toPublicSite(site) {
  return {
    id: site.id,
    host: site.host,
    displayName: site.displayName,
    upstreamUrl: site.upstreamUrl,
    enabled: site.enabled,
    oidc: {
      issuer: site.oidc.issuer,
      clientId: site.oidc.clientId,
      clientSecret: site.oidc.clientSecret ? "********" : "",
      scopes: site.oidc.scopes,
      redirectPath: site.oidc.redirectPath,
      postLogoutRedirectUrl: site.oidc.postLogoutRedirectUrl
    }
  };
}

function renderErrorPage(title, message) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${escapeHtml(title)}</title>
    <style>
      body { font-family: Georgia, serif; background: linear-gradient(135deg, #f8f4ea, #dbe9e2); color: #193229; margin: 0; }
      main { max-width: 720px; margin: 10vh auto; padding: 32px; background: rgba(255,255,255,0.82); border-radius: 24px; box-shadow: 0 24px 60px rgba(17,44,34,.12); }
      h1 { margin-top: 0; font-size: 2rem; }
      p { font-size: 1.05rem; line-height: 1.7; }
      a { color: #145c47; }
    </style>
  </head>
  <body>
    <main>
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(message)}</p>
    </main>
  </body>
</html>`;
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

module.exports = {
  createApp,
  renderErrorPage,
  toPublicSite
};
