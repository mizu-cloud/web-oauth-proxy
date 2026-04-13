# web-oauth-proxy

ホスト名ごとに別の OIDC 設定で保護できる Node.js 製のリバースプロキシです。  
管理画面は専用ホストで公開し、サイト URL と OIDC 設定を Web GUI で管理します。

## Features

- ホスト名ごとの upstream URL と OIDC 設定
- 管理画面も OIDC で保護
- SQLite による設定永続化
- ホスト単位で独立したセッション Cookie
- OIDC discovery による設定検証

## Environment Variables

- `PORT`: リッスンポート。既定値は `3000`
- `TRUST_PROXY`: `true` のとき `X-Forwarded-*` を信頼
- `DATABASE_URL`: SQLite ファイルパス。既定値は `./data/web-oauth-proxy.db`
- `ADMIN_HOST`: 管理画面用ホスト名
- `ADMIN_SESSION_SECRET`: セッション署名キー
- `APP_ENCRYPTION_KEY`: DB 内の秘密値暗号化キー。32 バイト以上推奨
- `ADMIN_OIDC_ISSUER`
- `ADMIN_OIDC_CLIENT_ID`
- `ADMIN_OIDC_CLIENT_SECRET`
- `ADMIN_OIDC_SCOPES`: 既定値は `openid profile email`
- `ADMIN_OIDC_REDIRECT_PATH`: 既定値は `/_admin/auth/callback`
- `ADMIN_POST_LOGOUT_REDIRECT_URL`: 任意

## Start

```bash
npm install
npm start
```

`.env` がある場合は、起動時に自動で読み込みます。

```bash
ADMIN_HOST=admin.example.com
ADMIN_SESSION_SECRET=replace-me
APP_ENCRYPTION_KEY=replace-me-too
ADMIN_OIDC_ISSUER=https://idp.example.com/realms/main
ADMIN_OIDC_CLIENT_ID=admin-client
ADMIN_OIDC_CLIENT_SECRET=super-secret
```

## PM2

```bash
npm run start:pm2
npm run restart:pm2
npm run stop:pm2
```

必要な OIDC 用環境変数は `.env` またはシェルで設定してから `pm2 start ecosystem.config.js` を実行してください。  
固定値を使いたい場合は `ecosystem.config.js` の `env` を更新します。

## Routes

- `https://<admin-host>/`: 管理画面
- `GET /api/sites`
- `POST /api/sites`
- `PUT /api/sites/:id`
- `DELETE /api/sites/:id`
- `POST /api/sites/:id/toggle`
- `/_auth/login`
- `/_auth/callback`
- `/_auth/logout`

## Notes

- TLS 終端は前段プロキシを前提にしています。
- 管理用 OIDC 設定は環境変数ブートストラップのみです。
- セッションはサーバメモリ保持です。設定は SQLite に永続化されます。
