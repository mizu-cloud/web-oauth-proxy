const { Issuer, generators } = require("openid-client");

class OidcService {
  constructor() {
    this.issuerCache = new Map();
  }

  async discover(issuerUrl) {
    if (!this.issuerCache.has(issuerUrl)) {
      this.issuerCache.set(issuerUrl, await Issuer.discover(issuerUrl));
    }

    return this.issuerCache.get(issuerUrl);
  }

  async validateConfiguration(config) {
    const issuer = await this.discover(config.issuer);
    return {
      authorizationEndpoint: issuer.metadata.authorization_endpoint,
      tokenEndpoint: issuer.metadata.token_endpoint,
      endSessionEndpoint: issuer.metadata.end_session_endpoint || ""
    };
  }

  async buildClient(config, redirectUri) {
    const issuer = await this.discover(config.issuer);
    return new issuer.Client({
      client_id: config.clientId,
      client_secret: config.clientSecret,
      id_token_signed_response_alg: "HS256",
      redirect_uris: [redirectUri],
      response_types: ["code"]
    });
  }

  generateState() {
    return generators.state();
  }

  generateNonce() {
    return generators.nonce();
  }

  buildAuthorizationUrl(client, redirectUri, scope, state, nonce) {
    return client.authorizationUrl({
      redirect_uri: redirectUri,
      scope,
      state,
      nonce
    });
  }

  async callback(client, redirectUri, params, checks) {
    return client.callback(redirectUri, params, checks);
  }
}

module.exports = {
  OidcService
};
