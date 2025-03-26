import {
  AuthConfiguration,
  getJwtConfiguration,
  getEmailConfiguration,
  MetadataOf,
  AuthInterface,
  getAuthInterface,
  getTwoFactorConfiguration,
} from "./config";
import { JwtService } from "./jwt";
import { EmailService } from "./email";
import { assert, assertNonNull, assertSchema, Schema } from "@mojsoski/assert";
import { TwoFactorService } from "./2fa";
import { OAuthService, RedirectState } from "./oauth";

export interface IAuthInfo {
  emailVerified: boolean;
  twoFactorConfigured: boolean;
  twoFactorPassed: boolean;
  email: string;
  id: string;
}

export interface IAuthUser<TUserMetadata> {
  id: string;
  metadata: TUserMetadata;
  email: string;
  password_hash: string;
  base32_secret?: string;
  authenticator_confirmed: boolean;
  email_verified: boolean;
}

export class AuthService<
  TAuthUser extends IAuthUser<any>,
  TAuthInfo extends IAuthInfo,
  TRegisterSchema extends Schema & { password: "string"; email: "string" }
> {
  #jwtService: JwtService<TAuthInfo>;
  #emaiLService: EmailService<MetadataOf<TAuthUser>>;
  #twoFactorService: TwoFactorService<TAuthUser>;
  #oauth: OAuthService;
  #interface: AuthInterface<TAuthUser, TAuthInfo, TRegisterSchema>;

  constructor(
    config: AuthConfiguration<TAuthUser, TAuthInfo, TRegisterSchema>
  ) {
    this.#interface = getAuthInterface(config.interface);
    this.#jwtService = new JwtService(getJwtConfiguration(config.jwt));
    this.#emaiLService = new EmailService(getEmailConfiguration(config.email));
    this.#twoFactorService = new TwoFactorService(
      getTwoFactorConfiguration(config.twofactor)
    );
    this.#oauth = new OAuthService(config.oauth);
  }

  async register(registrationDetails: unknown) {
    assertSchema(
      registrationDetails,
      this.#interface.registerSchema,
      "registrationDetails"
    );
    const passwordHash = this.#interface.hash(registrationDetails.password);

    const ref = registrationDetails as unknown as { password?: string };
    delete ref.password;

    const id = await this.#interface.create(registrationDetails, passwordHash);
    assertNonNull(id, "user.id");

    const user = await this.#interface.getUserById(id);
    assertNonNull(user, "user");

    await this.requestEmailVerification(
      id,
      registrationDetails.email,
      user.metadata
    );

    return this.#jwtService.createAuth(
      id,
      this.#interface.getInfo(user, { twoFactorStatus: "if_required" })
    );
  }

  async login(email: string, password: string) {
    const user = await this.#interface.getUserWithPassword(
      email,
      this.#interface.hash(password)
    );
    assert(user, "Invalid authentication details");

    return this.#jwtService.createAuth(
      user.id,
      this.#interface.getInfo(user, { twoFactorStatus: "if_required" })
    );
  }

  async requestEmailVerification(
    id: string,
    email: string,
    metadata: MetadataOf<TAuthUser>
  ) {
    const jwt = this.#jwtService.createEmailVerify(id);
    await this.#emaiLService.send(email, "verify", { ...metadata, jwt });
  }

  async requestPasswordReset(
    id: string,
    email: string,
    metadata: MetadataOf<TAuthUser>
  ) {
    const jwt = this.#jwtService.createReset(id);
    await this.#emaiLService.send(email, "reset", { ...metadata, jwt });
  }

  async preformPasswordReset(jwt: string, password: string) {
    const tokenData = this.#jwtService.verify(jwt, "reset");
    assert(tokenData, "Invalid JWT");

    const user = await this.#interface.getUserById(tokenData.sub);
    assert(user, "Cannot find user in database");

    await this.#interface.update(tokenData.sub, {
      password_hash: this.#interface.hash(password),
    } as Partial<TAuthUser>);

    return this.#jwtService.createAuth(
      tokenData.sub,
      this.#interface.getInfo(user, { twoFactorStatus: "if_required" })
    );
  }

  async preformEmailVerification(jwt: string) {
    const tokenData = this.#jwtService.verify(jwt, "verify");
    assert(tokenData, "Invalid JWT");

    const user = await this.#interface.getUserById(tokenData.sub);
    assert(user, "Cannot find user in database");

    await this.#interface.update(tokenData.sub, {
      email_verified: true,
    } as Partial<TAuthUser>);

    return this.#jwtService.createAuth(
      tokenData.sub,
      this.#interface.getInfo(user, { twoFactorStatus: "if_required" })
    );
  }

  async enableTwoFactor(user: TAuthUser) {
    const { url, secret } = this.#twoFactorService.enable(user);

    await this.#interface.update(user.id, {
      authenticator_confirmed: false,
      base32_secret: secret,
    } as Partial<TAuthUser>);

    user.authenticator_confirmed = false;
    user.base32_secret = secret;

    return { url, secret };
  }

  async resetTwoFactor(user: TAuthUser, token: string) {
    this.#twoFactorService.validate(user, token);
    const result = await this.enableTwoFactor(user);
    return {
      ...result,
      token: this.#jwtService.createAuth(
        user.id,
        this.#interface.getInfo(user, { twoFactorStatus: "reset" })
      ),
    };
  }

  async confirmTwoFactor(user: TAuthUser, token: string) {
    this.#twoFactorService.validate(user, token);
    await this.#interface.update(user.id, {
      authenticator_confirmed: true,
    } as Partial<TAuthUser>);

    user.authenticator_confirmed = true;

    return this.#jwtService.createAuth(
      user.id,
      this.#interface.getInfo(user, { twoFactorStatus: "ok" })
    );
  }

  async authenticateTwoFactor(user: TAuthUser, token: string) {
    this.#twoFactorService.validate(user, token);
    return this.#jwtService.createAuth(
      user.id,
      this.#interface.getInfo(user, { twoFactorStatus: "ok" })
    );
  }

  async createExternalRedirectUrl(provider: string) {
    return await this.#oauth.createRedirectUrl(provider);
  }

  async handleExternalRedirect(
    auth: TAuthInfo | undefined,
    provider: string,
    url: URL,
    state: RedirectState
  ): Promise<ExternalRedirectResponse> {
    const userInfo = await this.#oauth.handleRedirect(provider, url, state);

    if (auth) {
      await this.#interface.external.create(auth.id, provider, userInfo.sub);
      return { status: "linked" };
    }
    const user = await this.#interface.external.getUser(provider, userInfo.sub);
    if (user) {
      return {
        status: "login",
        token: this.#jwtService.createAuth(
          user.id,
          this.#interface.getInfo(user, { twoFactorStatus: "if_required" })
        ),
      };
    }

    return {
      status: "register",
      token: this.#jwtService.createExternalAuth(provider, userInfo),
    };
  }

  async externalRegister(registrationDetails: unknown, jwt: string) {
    const jwtPayload = this.#jwtService.verify(jwt, "external_auth");
    assertNonNull(jwtPayload, "Invalid token");

    const { userInfo, provider } = jwtPayload;
    assertSchema(
      registrationDetails,
      this.#interface.registerSchema,
      "registrationDetails"
    );
    const passwordHash = this.#interface.hash(registrationDetails.password);
    const ref = registrationDetails as unknown as { password?: string };
    delete ref.password;

    const emailVerified = userInfo.email_verified
      ? registrationDetails.email === userInfo.email
      : false;

    const metadata = this.#interface.external.getMetadata(
      registrationDetails,
      userInfo
    );

    const id = await this.#interface.create(registrationDetails, passwordHash);
    assertNonNull(id, "user.id");

    const user = await this.#interface.getUserById(id);
    assertNonNull(user, "user");

    await this.#interface.update(id, {
      metadata,
      email_verified: emailVerified,
    } as Partial<TAuthUser>);

    await this.#interface.external.create(id, provider, userInfo.sub);

    await this.requestEmailVerification(
      id,
      registrationDetails.email,
      user.metadata
    );

    return this.#jwtService.createAuth(
      id,
      this.#interface.getInfo(user, { twoFactorStatus: "if_required" })
    );
  }

  get externalProviders(): string[] {
    return this.#oauth.providers;
  }

  getInfo(jwt: string) {
    return this.#jwtService.verify(jwt, "auth")?.info;
  }

  hash(password: string) {
    return this.#interface.hash(password);
  }
}

export type ExternalRedirectResponse =
  | { status: "linked" }
  | { status: "login"; token: string }
  | { status: "register"; token: string };
