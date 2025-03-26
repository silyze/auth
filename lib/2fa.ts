import { encode } from "hi-base32";
import { TwoFactorConfig } from "./config";
import { randomBytes } from "crypto";
import { TOTP } from "otpauth";
import { IAuthUser } from ".";
import { assert } from "@mojsoski/assert";

function createBase32Secret() {
  const buffer = randomBytes(15);
  const base32 = encode(buffer).replace(/=/g, "").substring(0, 24);
  return base32;
}

function createAuthenticator<TAuthUser extends IAuthUser<any>>(
  config: TwoFactorConfig<TAuthUser>,
  user: TAuthUser,
  secret?: string
) {
  return new TOTP({
    issuer: config.TWO_FACTOR_ISSUER,
    label: config.getLabel(user),
    algorithm: "SHA1",
    digits: 6,
    secret: secret ?? user.base32_secret,
  });
}

export class TwoFactorService<TAuthUser extends IAuthUser<any>> {
  #config: TwoFactorConfig<TAuthUser>;
  constructor(config: TwoFactorConfig<TAuthUser>) {
    this.#config = config;
  }

  validate(user: TAuthUser, token: string) {
    const authenticator = createAuthenticator(this.#config, user);
    assert(
      authenticator.validate({
        token,
        window: this.#config.TWO_FACTOR_WINDOW,
      }) !== null,
      "Invalid token"
    );
  }

  enable(user: TAuthUser) {
    const secret = createBase32Secret();
    const authenticator = createAuthenticator(this.#config, user, secret);

    return {
      url: authenticator.toString(),
      secret: authenticator.secret.base32,
    };
  }
}
