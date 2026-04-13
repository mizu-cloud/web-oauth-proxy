const test = require("node:test");
const assert = require("node:assert/strict");
const supertest = require("supertest");
const { createApp } = require("../src/app");
const { encryptSecret, decryptSecret, hostCookieName } = require("../src/crypto");

function createRepositoryStub() {
  const sites = [
    {
      id: 1,
      host: "app.example.com",
      displayName: "App",
      upstreamUrl: "http://upstream.internal",
      enabled: true,
      oidc: {
        issuer: "https://issuer.example.com",
        clientId: "client",
        clientSecret: "secret",
        scopes: "openid profile email",
        redirectPath: "/_auth/callback",
        postLogoutRedirectUrl: ""
      }
    }
  ];

  return {
    listSites() {
      return sites;
    },
    getSiteById(id) {
      return sites.find((site) => site.id === id) || null;
    },
    getSiteByHost(host) {
      return sites.find((site) => site.host === host) || null;
    },
    createSite(input) {
      const site = { id: sites.length + 1, ...input };
      sites.push(site);
      return site;
    },
    updateSite(id, input) {
      const index = sites.findIndex((site) => site.id === id);
      sites[index] = { id, ...input };
      return sites[index];
    },
    deleteSite(id) {
      const index = sites.findIndex((site) => site.id === id);
      sites.splice(index, 1);
    }
  };
}

function createOidcStub() {
  return {
    async validateConfiguration() {
      return {};
    },
    async buildClient() {
      return {
        callbackParams(req) {
          return req.query;
        }
      };
    },
    generateState() {
      return "state-123";
    },
    generateNonce() {
      return "nonce-123";
    },
    buildAuthorizationUrl(_client, _redirectUri, _scope, state, nonce) {
      return `https://issuer.example.com/auth?state=${state}&nonce=${nonce}`;
    },
    async callback() {
      return {
        claims() {
          return {
            sub: "user-1",
            email: "user@example.com",
            name: "Test User"
          };
        }
      };
    }
  };
}

test("crypto roundtrip preserves secrets", () => {
  const encrypted = encryptSecret("super-secret", "encryption-key");
  assert.notEqual(encrypted, "super-secret");
  assert.equal(decryptSecret(encrypted, "encryption-key"), "super-secret");
});

test("hostCookieName is deterministic per host", () => {
  assert.equal(hostCookieName("site", "app.example.com"), hostCookieName("site", "app.example.com"));
  assert.notEqual(hostCookieName("site", "app.example.com"), hostCookieName("site", "other.example.com"));
});

test("admin API lists sites after auth session", async () => {
  const repository = createRepositoryStub();
  const { app } = createApp({
    config: {
      port: 0,
      trustProxy: false,
      databasePath: ":memory:",
      adminHost: "admin.example.com",
      adminSessionSecret: "secret",
      appEncryptionKey: "enc",
      adminOidc: {
        issuer: "https://issuer.example.com",
        clientId: "admin",
        clientSecret: "secret",
        scopes: "openid profile email",
        redirectPath: "/_admin/auth/callback",
        postLogoutRedirectUrl: ""
      }
    },
    repository,
    oidcService: createOidcStub()
  });

  const agent = supertest.agent(app);
  await agent.get("/_admin/auth/login").set("Host", "admin.example.com").expect(302);
  await agent.get("/_admin/auth/callback?code=abc&state=state-123").set("Host", "admin.example.com").expect(302);
  const response = await agent.get("/api/sites").set("Host", "admin.example.com").expect(200);
  assert.equal(response.body.sites.length, 1);
});

test("site host redirects unauthenticated users into OIDC flow", async () => {
  const { app } = createApp({
    config: {
      port: 0,
      trustProxy: false,
      databasePath: ":memory:",
      adminHost: "admin.example.com",
      adminSessionSecret: "secret",
      appEncryptionKey: "enc",
      adminOidc: {
        issuer: "https://issuer.example.com",
        clientId: "admin",
        clientSecret: "secret",
        scopes: "openid profile email",
        redirectPath: "/_admin/auth/callback",
        postLogoutRedirectUrl: ""
      }
    },
    repository: createRepositoryStub(),
    oidcService: createOidcStub()
  });

  const response = await supertest(app).get("/reports").set("Host", "app.example.com").expect(302);
  assert.match(response.headers.location, /^\/_auth\/login\?/);
});

test("custom site redirect path completes callback without redirect loop", async () => {
  const repository = createRepositoryStub();
  repository.getSiteByHost = () => ({
    id: 1,
    host: "app.example.com",
    displayName: "App",
    upstreamUrl: "http://127.0.0.1:9",
    enabled: true,
    oidc: {
      issuer: "https://issuer.example.com",
      clientId: "client",
      clientSecret: "secret",
      scopes: "openid profile email",
      redirectPath: "/oidc/custom-callback",
      postLogoutRedirectUrl: ""
    }
  });

  const { app } = createApp({
    config: {
      port: 0,
      trustProxy: false,
      databasePath: ":memory:",
      adminHost: "admin.example.com",
      adminSessionSecret: "secret",
      appEncryptionKey: "enc",
      adminOidc: {
        issuer: "https://issuer.example.com",
        clientId: "admin",
        clientSecret: "secret",
        scopes: "openid profile email",
        redirectPath: "/_admin/auth/callback",
        postLogoutRedirectUrl: ""
      }
    },
    repository,
    oidcService: createOidcStub()
  });

  const agent = supertest.agent(app);
  await agent
    .get("/_auth/login?returnTo=%2Freports")
    .set("Host", "app.example.com")
    .expect(302);

  const callbackResponse = await agent
    .get("/oidc/custom-callback?code=abc&state=state-123")
    .set("Host", "app.example.com")
    .expect(302);

  assert.equal(callbackResponse.headers.location, "/reports");
});
