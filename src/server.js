require("dotenv").config();

const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const { getConfig } = require("./config");
const { createDatabase } = require("./db");
const { createApp } = require("./app");

async function main() {
  const config = getConfig();
  const repository = await createDatabase(config.databaseUrl, config.appEncryptionKey);
  const sessionStore = new MySQLStore(
    {
      clearExpired: true,
      checkExpirationInterval: 15 * 60 * 1000,
      expiration: 24 * 60 * 60 * 1000
    },
    repository.pool
  );
  await sessionStore.onReady();
  const { app } = createApp({ config, repository, sessionStore });

  app.listen(config.port, () => {
    console.log(`web-oauth-proxy listening on ${config.port}`);
  });
}

main().catch((error) => {
  console.error("failed to start", error);
  process.exit(1);
});
