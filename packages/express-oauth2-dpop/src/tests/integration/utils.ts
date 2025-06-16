import { calculateJwkThumbprint, SignJWT } from "jose";
import type { JWTPayload } from "jose";

import { AUTH_BASE_URL, privateKey, publicJwk } from "./setup-jwks.js";
import { DEFAULT_AUDIENCE } from "./setup-api.js";

export async function generateAccessToken(
  payload: JWTPayload = {},
): Promise<string> {
  const {
    iat = Math.floor(Date.now() / 1000),
    exp = Math.floor(Date.now() / 1000) + 3600,
    jkt,
    aud = DEFAULT_AUDIENCE,
    scope,
  } = payload;

  publicJwk.kid = await calculateJwkThumbprint(publicJwk);
  publicJwk.use = "sig";
  publicJwk.alg = "RS256";

  const claims: JWTPayload = {
    sub: crypto.randomUUID(),
    iss: AUTH_BASE_URL,
    aud,
    iat,
    exp,
  };

  if (scope) {
    claims.scope = scope;
  }

  if (jkt) {
    claims.cnf = {
      jkt,
    };
  }

  return await new SignJWT(claims)
    .setProtectedHeader({ alg: publicJwk.alg, kid: publicJwk.kid })
    .sign(privateKey);
}
