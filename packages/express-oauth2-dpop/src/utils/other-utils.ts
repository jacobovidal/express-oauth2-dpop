import assert from "assert";

import { TOKEN_TYPE } from "../constants/constants.js";
import type { AuthMiddlewareOptions } from "../types/types.js";
import type { ParsedAuthorizationHeaders } from "../types/types.internal.js";

export function buildJwksUri(authOptions: AuthMiddlewareOptions): URL {
  const { issuer, jwksUri } = authOptions;

  if (jwksUri) {
    return new URL(jwksUri);
  }

  return new URL("/.well-known/jwks.json", issuer);
}

export function assertAuthOptions(authOptions: AuthMiddlewareOptions): void {
  assert(authOptions.issuer, "'issuer' must be provided in options");
  assert(authOptions.audience, "'audience' must be provided in options");
  assert(authOptions.nonceSecret, "'nonceSecret' must be provided in options");
  assert(
    Buffer.from(authOptions.nonceSecret, "utf8").length === 32,
    "'nonceSecret' must be 32 bytes"
  );
}

export function parseAuthorizationHeader(
  authorization?: string
): ParsedAuthorizationHeaders {
  if (!authorization) {
    return null;
  }

  const [type, accessToken] = authorization.split(" ");

  if (type === TOKEN_TYPE.BEARER && accessToken) {
    return { type: TOKEN_TYPE.BEARER, accessToken };
  }

  if (type === TOKEN_TYPE.DPOP && accessToken) {
    return { type: TOKEN_TYPE.DPOP, accessToken };
  }

  return null;
}
