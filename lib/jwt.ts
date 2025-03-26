import { sign, verify } from "jsonwebtoken";
import { UserInfoResponse } from "openid-client";
import { JwtConfig } from "./config";

export type JwtType =
  | "reset"
  | "verify"
  | "auth"
  | "external_auth"
  | `basic+${string}`;

export type JwtPayload<
  T extends "reset" | "verify" | "auth" | "external_auth" | `basic+${string}`,
  TAuthInfo
> = T extends `basic+${string}`
  ? { use: T; payload: object }
  : T extends "auth"
  ? { use: T; sub: string; info: TAuthInfo }
  : T extends "external_auth"
  ? { use: T; userInfo: UserInfoResponse; provider: string }
  : { use: T; sub: string };

function verifyBasicJwt<T extends object>(
  config: JwtConfig,
  jwt: string,
  use: string
) {
  return verifyJwt(config, jwt, `basic+${use}`)?.payload as T | null;
}

function verifyJwt<T extends JwtType, TAuthInfo>(
  config: JwtConfig,
  jwt: string,
  use: T
) {
  const payload = verify(jwt, config.JWT_TOKEN) as object;
  if (
    "use" in payload &&
    typeof payload.use === "string" &&
    payload.use === use
  ) {
    return payload as JwtPayload<T, TAuthInfo>;
  }
  return null;
}

function createBasicJwt<T extends object>(
  config: JwtConfig,
  use: string,
  payload: T
) {
  return sign(
    {
      use: `basic+${use}`,
      payload,
    },
    config.JWT_TOKEN,
    {
      algorithm: "HS256",
      expiresIn: config.BASIC_JWT_DURATION,
    }
  );
}

function createExternalAuthJwt(
  config: JwtConfig,
  provider: string,
  userInfo: UserInfoResponse
) {
  return sign(
    {
      use: "external_auth",
      userInfo,
      provider,
    },
    config.JWT_TOKEN,
    {
      algorithm: "HS256",
      expiresIn: config.EXTERNAL_REGISTER_JWT_TOKEN_DURATION,
    }
  );
}

function createEmailVerifyJwt(config: JwtConfig, id: string) {
  return sign(
    {
      use: "verify",
    },
    config.JWT_TOKEN,
    {
      algorithm: "HS256",
      expiresIn: config.VERIFY_EMAIL_JWT_TOKEN_DURATION,
      subject: id,
    }
  );
}

function createResetJwt(config: JwtConfig, id: string) {
  return sign(
    {
      use: "reset",
    },
    config.JWT_TOKEN,
    {
      algorithm: "HS256",
      expiresIn: config.RESET_PASSWORD_JWT_TOKEN_DURATION,
      subject: id,
    }
  );
}

function createAuthJwt<TAuthInfo>(
  config: JwtConfig,
  id: string,
  info: TAuthInfo
) {
  return sign(
    {
      use: "auth",
      info,
    },
    config.JWT_TOKEN,
    {
      algorithm: "HS256",
      expiresIn: config.JWT_TOKEN_DURATION,
      subject: id,
    }
  );
}

export class JwtService<TAuthInfo> {
  #config: JwtConfig;
  constructor(config: JwtConfig) {
    this.#config = config;
  }

  createAuth(id: string, info: TAuthInfo) {
    return createAuthJwt(this.#config, id, info);
  }

  createReset(id: string) {
    return createResetJwt(this.#config, id);
  }

  createEmailVerify(id: string) {
    return createEmailVerifyJwt(this.#config, id);
  }

  createExternalAuth(provider: string, userInfo: UserInfoResponse) {
    return createExternalAuthJwt(this.#config, provider, userInfo);
  }

  createBasic<T extends object>(use: string, payload: T) {
    return createBasicJwt(this.#config, use, payload);
  }

  verify<T extends JwtType>(jwt: string, use: T) {
    return verifyJwt<T, TAuthInfo>(this.#config, jwt, use);
  }

  verfiyBasic<T extends object>(jwt: string, use: string) {
    return verifyBasicJwt<T>(this.#config, jwt, use);
  }
}
