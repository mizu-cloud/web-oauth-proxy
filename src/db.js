const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const { encryptSecret, decryptSecret } = require("./crypto");
const { normalizeHost } = require("./config");

function createDatabase(databasePath, encryptionSecret) {
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  const db = new Database(databasePath);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  migrate(db);

  const statements = {
    listSites: db.prepare(`
      SELECT
        s.id,
        s.host,
        s.display_name,
        s.upstream_url,
        s.enabled,
        s.created_at,
        s.updated_at,
        o.issuer,
        o.client_id,
        o.client_secret,
        o.scopes,
        o.redirect_path,
        o.post_logout_redirect_url
      FROM sites s
      JOIN oidc_configs o ON o.site_id = s.id
      ORDER BY s.host ASC
    `),
    getSiteById: db.prepare(`
      SELECT
        s.id,
        s.host,
        s.display_name,
        s.upstream_url,
        s.enabled,
        s.created_at,
        s.updated_at,
        o.issuer,
        o.client_id,
        o.client_secret,
        o.scopes,
        o.redirect_path,
        o.post_logout_redirect_url
      FROM sites s
      JOIN oidc_configs o ON o.site_id = s.id
      WHERE s.id = ?
    `),
    getSiteByHost: db.prepare(`
      SELECT
        s.id,
        s.host,
        s.display_name,
        s.upstream_url,
        s.enabled,
        s.created_at,
        s.updated_at,
        o.issuer,
        o.client_id,
        o.client_secret,
        o.scopes,
        o.redirect_path,
        o.post_logout_redirect_url
      FROM sites s
      JOIN oidc_configs o ON o.site_id = s.id
      WHERE s.host = ?
    `),
    insertSite: db.prepare(`
      INSERT INTO sites (host, display_name, upstream_url, enabled)
      VALUES (@host, @displayName, @upstreamUrl, @enabled)
    `),
    insertOidc: db.prepare(`
      INSERT INTO oidc_configs (
        site_id,
        issuer,
        client_id,
        client_secret,
        scopes,
        redirect_path,
        post_logout_redirect_url
      )
      VALUES (
        @siteId,
        @issuer,
        @clientId,
        @clientSecret,
        @scopes,
        @redirectPath,
        @postLogoutRedirectUrl
      )
    `),
    updateSite: db.prepare(`
      UPDATE sites
      SET host = @host,
          display_name = @displayName,
          upstream_url = @upstreamUrl,
          enabled = @enabled,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = @id
    `),
    updateOidc: db.prepare(`
      UPDATE oidc_configs
      SET issuer = @issuer,
          client_id = @clientId,
          client_secret = @clientSecret,
          scopes = @scopes,
          redirect_path = @redirectPath,
          post_logout_redirect_url = @postLogoutRedirectUrl,
          updated_at = CURRENT_TIMESTAMP
      WHERE site_id = @siteId
    `),
    deleteSite: db.prepare(`DELETE FROM sites WHERE id = ?`)
  };

  function hydrate(row) {
    if (!row) {
      return null;
    }

    return {
      id: row.id,
      host: row.host,
      displayName: row.display_name,
      upstreamUrl: row.upstream_url,
      enabled: Boolean(row.enabled),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      oidc: {
        issuer: row.issuer,
        clientId: row.client_id,
        clientSecret: decryptSecret(row.client_secret, encryptionSecret),
        scopes: row.scopes,
        redirectPath: row.redirect_path,
        postLogoutRedirectUrl: row.post_logout_redirect_url || ""
      }
    };
  }

  const createSite = db.transaction((input) => {
    const siteResult = statements.insertSite.run({
      host: normalizeHost(input.host),
      displayName: input.displayName,
      upstreamUrl: input.upstreamUrl,
      enabled: input.enabled ? 1 : 0
    });

    statements.insertOidc.run({
      siteId: siteResult.lastInsertRowid,
      issuer: input.oidc.issuer,
      clientId: input.oidc.clientId,
      clientSecret: encryptSecret(input.oidc.clientSecret, encryptionSecret),
      scopes: input.oidc.scopes,
      redirectPath: input.oidc.redirectPath,
      postLogoutRedirectUrl: input.oidc.postLogoutRedirectUrl || ""
    });

    return getSiteById(Number(siteResult.lastInsertRowid));
  });

  const updateSite = db.transaction((id, input) => {
    statements.updateSite.run({
      id,
      host: normalizeHost(input.host),
      displayName: input.displayName,
      upstreamUrl: input.upstreamUrl,
      enabled: input.enabled ? 1 : 0
    });

    statements.updateOidc.run({
      siteId: id,
      issuer: input.oidc.issuer,
      clientId: input.oidc.clientId,
      clientSecret: encryptSecret(input.oidc.clientSecret, encryptionSecret),
      scopes: input.oidc.scopes,
      redirectPath: input.oidc.redirectPath,
      postLogoutRedirectUrl: input.oidc.postLogoutRedirectUrl || ""
    });

    return getSiteById(id);
  });

  function getSiteById(id) {
    return hydrate(statements.getSiteById.get(id));
  }

  return {
    db,
    listSites() {
      return statements.listSites.all().map(hydrate);
    },
    getSiteById,
    getSiteByHost(host) {
      return hydrate(statements.getSiteByHost.get(normalizeHost(host)));
    },
    createSite,
    updateSite,
    deleteSite(id) {
      statements.deleteSite.run(id);
    }
  };
}

function migrate(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS sites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      host TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      upstream_url TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS oidc_configs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id INTEGER NOT NULL UNIQUE REFERENCES sites(id) ON DELETE CASCADE,
      issuer TEXT NOT NULL,
      client_id TEXT NOT NULL,
      client_secret TEXT NOT NULL,
      scopes TEXT NOT NULL,
      redirect_path TEXT NOT NULL DEFAULT '/_auth/callback',
      post_logout_redirect_url TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

module.exports = {
  createDatabase
};
