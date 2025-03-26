import {
  authorizationCodeGrant,
  buildAuthorizationUrl,
  calculatePKCECodeChallenge,
  discovery,
  fetchUserInfo,
  randomPKCECodeVerifier,
  randomState,
  skipSubjectCheck,
} from "openid-client";
import { assert } from "@mojsoski/assert";
import { assertNonNull } from "@mojsoski/assert";
import { OAuthConfig, OAuthProviderConfig } from "./config";

function getConfigurationFromEnvionment(
  provider: string
): Partial<OAuthProviderConfig> {
  const urlEnv = `OPENID_PROVIDER_${provider.toUpperCase()}`;
  const clientIdEnv = `OPENID_PROVIDER_${provider.toUpperCase()}_CLIENT_ID`;
  const clientSecretEnv = `OPENID_PROVIDER_${provider.toUpperCase()}_CLIENT_SECRET`;

  const url =
    process.env[urlEnv] !== undefined
      ? new URL(process.env[urlEnv])
      : undefined;

  const clientId = process.env[clientIdEnv];
  const clientSecret = process.env[clientSecretEnv];
  return { url, clientId, clientSecret };
}
function getProvidersFromEnvironment(): [
  string,
  Partial<OAuthProviderConfig>
][] {
  return (process.env.OPENID_PROVIDERS?.split(",") ?? []).map((provider) => [
    provider,
    getConfigurationFromEnvionment(provider),
  ]);
}

export type RedirectState = { code_verifier: string; state: string };

async function handleRedirect(
  oauth: OAuthConfig,
  provider: string,
  url: URL,
  { code_verifier, state }: RedirectState
) {
  const providerConfig = oauth.providers[provider];
  assertNonNull(providerConfig, `oauth.providers[${provider}]`);
  const config = await discovery(
    providerConfig.url,
    providerConfig.clientId,
    providerConfig.clientSecret
  );

  const tokens = await authorizationCodeGrant(config, new URL(url), {
    pkceCodeVerifier: code_verifier,
    expectedState: state === "local" ? undefined : state,
  });

  return await fetchUserInfo(config, tokens.access_token, skipSubjectCheck);
}

async function createRedirectUrl(oauth: OAuthConfig, provider: string) {
  assertNonNull(process.env.PUBLIC_URL, "PUBLIC_URL");

  const providerConfig = oauth.providers[provider];
  assertNonNull(providerConfig, `oauth.providers[${provider}]`);
  const config = await discovery(
    providerConfig.url,
    providerConfig.clientId,
    providerConfig.clientSecret
  );

  const redirect_uri = oauth.getRedirectUrl(provider);
  const scope: string = oauth.getScopes(provider);

  const code_verifier: string = randomPKCECodeVerifier();
  const code_challenge: string = await calculatePKCECodeChallenge(
    code_verifier
  );

  let state = "local";
  const parameters: Record<string, string> = {
    redirect_uri,
    scope,
    code_challenge,
    code_challenge_method: "S256",
  };

  if (!config.serverMetadata().supportsPKCE()) {
    state = randomState();
    parameters.state = state;
  }

  const redirectUrl = buildAuthorizationUrl(config, parameters);

  return { redirectUrl, code_verifier, state };
}

export class OAuthService {
  #config: OAuthConfig;
  constructor(config: OAuthConfig) {
    this.#config = { ...config, providers: { ...config.providers } };

    for (const [provider, providerConfig] of getProvidersFromEnvironment()) {
      if (!this.#config.providers[provider]) {
        assertNonNull(providerConfig.clientId, `${provider}.clientId`);
        assertNonNull(providerConfig.clientSecret, `${provider}.clientSecret`);
        assertNonNull(providerConfig.url, `${provider}.url`);

        this.#config.providers[provider] =
          providerConfig as OAuthProviderConfig;

        continue;
      }

      if (providerConfig.clientId) {
        this.#config.providers[provider].clientId ??= providerConfig.clientId;
      }

      if (providerConfig.clientSecret) {
        this.#config.providers[provider].clientSecret ??=
          providerConfig.clientSecret;
      }

      if (providerConfig.url) {
        this.#config.providers[provider].url ??= providerConfig.url;
      }
    }
  }

  async handleRedirect(provider: string, url: URL, state: RedirectState) {
    return await handleRedirect(this.#config, provider, url, state);
  }

  async createRedirectUrl(provider: string) {
    return await createRedirectUrl(this.#config, provider);
  }

  get providers(): string[] {
    return Object.keys(this.#config.providers);
  }
}
