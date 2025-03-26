import { assertNonNull } from "@mojsoski/assert";
import { AuthService, IAuthInfo, IAuthUser } from "./lib";

interface UserMetadata {
  firstName: string;
  lastName: string;
}

interface User extends IAuthUser<UserMetadata> {}
interface ExternalAuth {
  id: string;
  provider: string;
  providerId: string;
}

interface AuthInfo extends IAuthInfo {}

const users = new Map<string, User>();
const externalAuth = new Map<string, ExternalAuth>();
let lastUserId = 0;

const registerSchema = {
  email: "string",
  password: "string",
  firstName: "string",
  lastName: "string",
} as const;

type RegisterSchema = typeof registerSchema;

const authService = new AuthService<User, AuthInfo, RegisterSchema>({
  jwt: {
    JWT_TOKEN: "welUOpIN1fM6hOHBjXaudnVUp0jvmbbT",
  },
  oauth: {
    providers: {},
    getRedirectUrl(provider) {
      return `/external/${provider}`;
    },
    getScopes() {
      return `openid`;
    },
  },
  email: {
    smtp: false,
    async sendMessage(message) {
      console.log(message);
    },
    templates: {
      reset({ firstName, jwt }) {
        return {
          subject: "Password Reset Request",
          text: `Hello, ${firstName}! Go to /reset/${jwt} to reset your password.`,
          html: `Hello, ${firstName}! Go to /reset/${jwt} to reset your password.`,
        };
      },
      verify({ firstName, jwt }) {
        return {
          subject: "Email Verification Request",
          text: `Hello, ${firstName}! Go to /verify/${jwt} to verify your email.`,
          html: `Hello, ${firstName}! Go to /verify/${jwt} to verify your email.`,
        };
      },
    },
  },
  interface: {
    registerSchema,

    getInfo(user, context) {
      const twoFactorConfigured = !!(
        user.base32_secret && user.authenticator_confirmed
      );
      return {
        id: user.id,
        email: user.email,
        emailVerified: user.email_verified,
        twoFactorConfigured,
        twoFactorPassed:
          context.twoFactorStatus === "ok" ||
          (context.twoFactorStatus === "if_required" && !twoFactorConfigured),
      };
    },

    async getUserWithPassword(email, passwordHash) {
      return users
        .values()
        .find(
          (user) => user.email === email && user.password_hash === passwordHash
        );
    },

    async getUserById(id) {
      return users.get(id);
    },

    async update(id, data) {
      const user = users.get(id);
      assertNonNull(user, "User was not found");
      users.set(id, { ...user, ...data });
    },

    async create(registrationDetails, passwordHash) {
      const id = (++lastUserId).toString();
      users.set(id, {
        id,
        email: registrationDetails.email,
        password_hash: passwordHash,
        email_verified: false,
        authenticator_confirmed: false,
        metadata: {
          firstName: registrationDetails.firstName,
          lastName: registrationDetails.lastName,
        },
      });
      return id;
    },

    async delete(id) {
      users.delete(id);
    },

    external: {
      getMetadata(registrationDetails, userInfo) {
        return {
          firstName: userInfo.given_name ?? registrationDetails.firstName,
          lastName: userInfo.family_name ?? registrationDetails.lastName,
        };
      },
      async create(id, provider, providerId) {
        const key = `${provider}|${providerId}`;
        externalAuth.set(key, { id, provider, providerId });
      },
      async delete(_id, provider, providerId) {
        const key = `${provider}|${providerId}`;
        externalAuth.delete(key);
      },
      async getUser(provider, providerId) {
        const key = `${provider}|${providerId}`;
        const auth = externalAuth.get(key);
        if (!auth) {
          return undefined;
        }

        return users.get(auth.id);
      },
    },
  },
});

async function main() {
  await authService.register({
    email: "test-1@example.com",
    firstName: "Test",
    lastName: "Test",
    password: "1234",
  });

  // replace this with the email verification token from the console.log
  await authService.preformEmailVerification(
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2UiOiJ2ZXJpZnkiLCJpYXQiOjE3NDMwMTU4NTgsImV4cCI6MTc3NDExOTg1OCwic3ViIjoiMSJ9.9s5QM8TIopKqXkynxJUJcIPbpUR3ruOWbfOvHKBPkFc"
  );

  const loginToken = await authService.login("test-1@example.com", "1234");
  const loginInfo = authService.getInfo(loginToken);

  console.log({ loginToken, loginInfo });

  const helloWorldJwt = authService.jwt.createBasic("test", { hello: "world" });
  const helloWorldPayload = authService.jwt.verfiyBasic(helloWorldJwt, "test");

  console.log({ helloWorldJwt, helloWorldPayload });
}

main().then();
