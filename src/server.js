require("dotenv").config();

const { createApp } = require("./app");

const { app, config } = createApp();

app.listen(config.port, () => {
  console.log(`web-oauth-proxy listening on ${config.port}`);
});
