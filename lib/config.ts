import { assertNonNull, Schema, SchemaResult } from "@mojsoski/assert";
import { EmailTemplates } from "./email";
import { IAuthInfo, IAuthUser } from "./index";
import { DEFAULT_ISSUER, defaultHash, defaultGetLabel } from "./defaults";
import { UserInfoResponse } from "openid-client";

export type MetadataOf<TAuthUser extends IAuthUser<any>> =
  TAuthUser extends IAuthUser<infer TMetadata> ? TMetadata : never;

export type OAuthProviderConfig = {
  url: URL;
  clientId: string;
  clientSecret: string;
};

export type OAuthConfig = {
  providers: Record<string, OAuthProviderConfig | undefined>;
  getRedirectUrl: (provider: string) => string;
  getScopes: (provider: string) => string;
};

export interface AuthConfiguration<
  TAuthUser extends IAuthUser<any>,
  TAuthInfo extends IAuthInfo,
  TRegisterSchema extends Schema
> {
  interface: AuthInterfaceSetup<TAuthUser, TAuthInfo, TRegisterSchema>;
  jwt?: Partial<JwtConfig>;
  twofactor?: Partial<TwoFactorConfig<TAuthUser>>;
  email: EmailConfigSetup<MetadataOf<TAuthUser>>;
  oauth: OAuthConfig;
}
export interface TwoFactorConfig<TAuthUser extends IAuthUser<any>> {
  TWO_FACTOR_WINDOW?: number;
  TWO_FACTOR_ISSUER: string;
  getLabel: (user: TAuthUser) => string;
}

type EmailSenderConfigSetup =
  | {
      smtp?: Partial<SmtpConfig>;
    }
  | {
      smtp: false;
      sendMessage: (message: EmailSenderMessage) => Promise<void>;
    };

type EmailConfigSetup<TMetadata> = EmailSenderConfigSetup & {
  templates: EmailTemplates<TMetadata>;
};

interface AuthInterfaceSetup<
  TAuthUser extends IAuthUser<any>,
  TAuthInfo extends IAuthInfo,
  TRegisterSchema extends Schema
> {
  hash?: (password: string) => string;

  registerSchema: TRegisterSchema;

  getInfo: (user: TAuthUser, context: AuthContext) => TAuthInfo;

  getUserWithPassword: (
    email: string,
    passwordHash: string
  ) => Promise<TAuthUser | undefined>;

  getUserById: (id: string) => Promise<TAuthUser | undefined>;

  update: (id: string, data: Partial<TAuthUser>) => Promise<void>;

  create: (
    registrationDetails: Omit<SchemaResult<TRegisterSchema>, "password">,
    passwordHash: string
  ) => Promise<string | undefined>;

  delete: (id: string) => Promise<void>;

  external: {
    getMetadata: (
      registrationDetails: Omit<SchemaResult<TRegisterSchema>, "password">,
      userInfo: UserInfoResponse
    ) => MetadataOf<TAuthUser>;

    getUser: (
      provider: string,
      providerId: string
    ) => Promise<TAuthUser | undefined>;
    create: (id: string, provider: string, providerId: string) => Promise<void>;
    delete: (id: string, provider: string, providerId: string) => Promise<void>;
  };
}

export type AuthContext = {
  twoFactorStatus: "ok" | "if_required" | "reset";
};

export interface AuthInterface<
  TAuthUser extends IAuthUser<any>,
  TAuthInfo extends IAuthInfo,
  TRegisterSchema extends Schema
> {
  hash: (password: string) => string;

  registerSchema: TRegisterSchema;

  getInfo: (user: TAuthUser, context: AuthContext) => TAuthInfo;

  getUserWithPassword: (
    email: string,
    passwordHash: string
  ) => Promise<TAuthUser | undefined>;

  getUserById: (id: string) => Promise<TAuthUser | undefined>;

  update: (id: string, data: Partial<TAuthUser>) => Promise<void>;

  create: (
    registrationDetails: Omit<SchemaResult<TRegisterSchema>, "password">,
    passwordHash: string
  ) => Promise<string | undefined>;

  delete: (id: string) => Promise<void>;

  external: {
    getMetadata: (
      registrationDetails: Omit<SchemaResult<TRegisterSchema>, "password">,
      userInfo: UserInfoResponse
    ) => MetadataOf<TAuthUser>;
    getUser: (
      provider: string,
      providerId: string
    ) => Promise<TAuthUser | undefined>;
    create: (id: string, provider: string, providerId: string) => Promise<void>;
    delete: (id: string, provider: string, providerId: string) => Promise<void>;
  };
}

export interface JwtConfig {
  JWT_TOKEN_DURATION: number;
  VERIFY_EMAIL_JWT_TOKEN_DURATION: number;
  RESET_PASSWORD_JWT_TOKEN_DURATION: number;
  EXTERNAL_REGISTER_JWT_TOKEN_DURATION: number;
  BASIC_JWT_DURATION: number;
  JWT_TOKEN: string;
}

export interface SmtpConfig {
  SMTP_PORT: number;
  SMTP_HOST: string;
  SMTP_EMAIL: string;
  SMTP_PASSWORD: string;
}
export type EmailSenderMessage = {
  subject: string;
  html: string;
  text: string;
  to: string;
};

type EmailSenderConfig =
  | {
      smtp: SmtpConfig;
    }
  | {
      smtp: false;
      sendMessage: (message: EmailSenderMessage) => Promise<void>;
    };

export type EmailConfig<TUserMetadata> = EmailSenderConfig & {
  templates: EmailTemplates<TUserMetadata>;
};

export function getTwoFactorConfiguration<TAuthUser extends IAuthUser<any>>(
  config?: Partial<TwoFactorConfig<TAuthUser>>
): TwoFactorConfig<TAuthUser> {
  return {
    TWO_FACTOR_WINDOW:
      config?.TWO_FACTOR_WINDOW ??
      (process.env.TWO_FACTOR_WINDOW !== undefined
        ? Number(process.env.TWO_FACTOR_WINDOW)
        : undefined),
    TWO_FACTOR_ISSUER:
      config?.TWO_FACTOR_ISSUER ??
      process.env.TWO_FACTOR_ISSUER ??
      DEFAULT_ISSUER,
    getLabel: config?.getLabel ?? defaultGetLabel,
  };
}

export function getEmailConfiguration<TUserMetadata>(
  config: EmailConfigSetup<TUserMetadata>
): EmailConfig<TUserMetadata> {
  if (config.smtp === false) {
    return {
      templates: config.templates,
      smtp: false,
      sendMessage: config.sendMessage,
    };
  }
  const SMTP_PORT = config.smtp?.SMTP_PORT ?? process.env.SMTP_PORT;
  const SMTP_HOST = config.smtp?.SMTP_HOST ?? process.env.SMTP_HOST;
  const SMTP_EMAIL = config.smtp?.SMTP_EMAIL ?? process.env.SMTP_EMAIL;
  const SMTP_PASSWORD = config.smtp?.SMTP_PASSWORD ?? process.env.SMTP_PASSWORD;
  assertNonNull(SMTP_PORT, "SMTP_PORT");
  assertNonNull(SMTP_HOST, "SMTP_HOST");
  assertNonNull(SMTP_EMAIL, "SMTP_EMAIL");
  assertNonNull(SMTP_PASSWORD, "SMTP_PASSWORD");

  return {
    templates: config.templates,
    smtp: {
      SMTP_HOST,
      SMTP_EMAIL,
      SMTP_PASSWORD,
      SMTP_PORT: Number(SMTP_PORT),
    },
  };
}

export function getAuthInterface<
  TAuthUser extends IAuthUser<any>,
  TAuthInfo extends IAuthInfo,
  TRegisterSchema extends Schema
>(
  config: AuthInterfaceSetup<TAuthUser, TAuthInfo, TRegisterSchema>
): AuthInterface<TAuthUser, TAuthInfo, TRegisterSchema> {
  return { ...config, hash: config.hash ?? defaultHash };
}

export function getJwtConfiguration(config?: Partial<JwtConfig>): JwtConfig {
  const JWT_TOKEN = config?.JWT_TOKEN ?? process.env.JWT_TOKEN;
  const DEFAULT_JWT_TOKEN_DURATION = 60 * 60 * 24 * 30;
  const DEFUALT_VERIFY_EMAIL_JWT_TOKEN_DURATION = 60 * 60 * 24 * 30 * 12;
  const DEFAULT_RESET_PASSWORD_JWT_TOKEN_DURATION = 60 * 60 * 24;
  const DEFAULT_EXTERNAL_REGISTER_JWT_TOKEN_DURATION = 60 * 60 * 24 * 30 * 12;
  const DEFAULT_BASIC_JWT_DURATION = 60 * 60 * 24;
  assertNonNull(JWT_TOKEN, "JWT_TOKEN environment variable is not set");

  return {
    JWT_TOKEN,
    JWT_TOKEN_DURATION:
      config?.JWT_TOKEN_DURATION ?? DEFAULT_JWT_TOKEN_DURATION,
    VERIFY_EMAIL_JWT_TOKEN_DURATION:
      config?.VERIFY_EMAIL_JWT_TOKEN_DURATION ??
      DEFUALT_VERIFY_EMAIL_JWT_TOKEN_DURATION,
    RESET_PASSWORD_JWT_TOKEN_DURATION:
      config?.RESET_PASSWORD_JWT_TOKEN_DURATION ??
      DEFAULT_RESET_PASSWORD_JWT_TOKEN_DURATION,
    EXTERNAL_REGISTER_JWT_TOKEN_DURATION:
      config?.EXTERNAL_REGISTER_JWT_TOKEN_DURATION ??
      DEFAULT_EXTERNAL_REGISTER_JWT_TOKEN_DURATION,
    BASIC_JWT_DURATION:
      config?.BASIC_JWT_DURATION ?? DEFAULT_BASIC_JWT_DURATION,
  };
}
