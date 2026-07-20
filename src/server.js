require("dotenv").config();

const { getConfig } = require("./config");
const { createDatabase } = require("./db");
const { createApp } = require("./app");

async function main() {
  const config = getConfig();
  const repository = await createDatabase(config.databaseUrl, config.appEncryptionKey);
  const { app } = createApp({ config, repository });

  app.listen(config.port, () => {
    console.log(`web-oauth-proxy listening on ${config.port}`);
  });
}

main().catch((error) => {
  console.error("failed to start", error);
  process.exit(1);
});
