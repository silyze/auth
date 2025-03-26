import { createHash } from "crypto";
import { IAuthUser } from ".";

export function defaultHash(password: string): string {
  return createHash("sha256").update(password).digest("hex");
}

export const DEFAULT_ISSUER = "@silyze/auth";

export function defaultGetLabel(user: IAuthUser<unknown>) {
  return user.email;
}
