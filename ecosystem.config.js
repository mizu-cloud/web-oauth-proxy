module.exports = {
  apps: [
    {
      name: "web-oauth-proxy",
      script: "./src/server.js",
      cwd: __dirname,
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      watch: false,
      max_memory_restart: "300M",
      env: {
        NODE_ENV: "production",
        PORT: 3000,
        TRUST_PROXY: "true",
        DATABASE_URL: "mysql://root@127.0.0.1:3306/web_oauth_proxy"
      }
    }
  ]
};
