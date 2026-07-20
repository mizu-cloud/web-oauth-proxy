const mysql = require("mysql2/promise");
const { encryptSecret, decryptSecret } = require("./crypto");
const { normalizeHost } = require("./config");

const SITE_SELECT = `
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
`;

async function createDatabase(databaseUrl, encryptionSecret) {
  const pool = mysql.createPool({
    uri: databaseUrl,
    waitForConnections: true,
    connectionLimit: 10,
    dateStrings: true
  });

  await migrate(pool);

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

  async function getSiteById(id) {
    const [rows] = await pool.query(`${SITE_SELECT} WHERE s.id = ?`, [id]);
    return hydrate(rows[0]);
  }

  async function withTransaction(work) {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const result = await work(connection);
      await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  return {
    pool,
    async listSites() {
      const [rows] = await pool.query(`${SITE_SELECT} ORDER BY s.host ASC`);
      return rows.map(hydrate);
    },
    getSiteById,
    async getSiteByHost(host) {
      const [rows] = await pool.query(`${SITE_SELECT} WHERE s.host = ?`, [normalizeHost(host)]);
      return hydrate(rows[0]);
    },
    async createSite(input) {
      const siteId = await withTransaction(async (connection) => {
        const [siteResult] = await connection.query(
          `INSERT INTO sites (host, display_name, upstream_url, enabled) VALUES (?, ?, ?, ?)`,
          [normalizeHost(input.host), input.displayName, input.upstreamUrl, input.enabled ? 1 : 0]
        );

        await connection.query(
          `INSERT INTO oidc_configs (
            site_id, issuer, client_id, client_secret, scopes, redirect_path, post_logout_redirect_url
          ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            siteResult.insertId,
            input.oidc.issuer,
            input.oidc.clientId,
            encryptSecret(input.oidc.clientSecret, encryptionSecret),
            input.oidc.scopes,
            input.oidc.redirectPath,
            input.oidc.postLogoutRedirectUrl || ""
          ]
        );

        return siteResult.insertId;
      });

      return getSiteById(siteId);
    },
    async updateSite(id, input) {
      await withTransaction(async (connection) => {
        await connection.query(
          `UPDATE sites SET host = ?, display_name = ?, upstream_url = ?, enabled = ? WHERE id = ?`,
          [normalizeHost(input.host), input.displayName, input.upstreamUrl, input.enabled ? 1 : 0, id]
        );

        await connection.query(
          `UPDATE oidc_configs
           SET issuer = ?, client_id = ?, client_secret = ?, scopes = ?, redirect_path = ?, post_logout_redirect_url = ?
           WHERE site_id = ?`,
          [
            input.oidc.issuer,
            input.oidc.clientId,
            encryptSecret(input.oidc.clientSecret, encryptionSecret),
            input.oidc.scopes,
            input.oidc.redirectPath,
            input.oidc.postLogoutRedirectUrl || "",
            id
          ]
        );
      });

      return getSiteById(id);
    },
    async deleteSite(id) {
      await pool.query(`DELETE FROM sites WHERE id = ?`, [id]);
    },
    async close() {
      await pool.end();
    }
  };
}

async function migrate(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sites (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      host VARCHAR(255) NOT NULL UNIQUE,
      display_name VARCHAR(255) NOT NULL,
      upstream_url TEXT NOT NULL,
      enabled TINYINT(1) NOT NULL DEFAULT 1,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS oidc_configs (
      id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
      site_id INT UNSIGNED NOT NULL UNIQUE,
      issuer TEXT NOT NULL,
      client_id TEXT NOT NULL,
      client_secret TEXT NOT NULL,
      scopes TEXT NOT NULL,
      redirect_path VARCHAR(255) NOT NULL DEFAULT '/_auth/callback',
      post_logout_redirect_url TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_oidc_configs_site FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4
  `);
}

module.exports = {
  createDatabase
};
