import assert from "assert";
import {
  createRemoteJWKSet,
  jwtVerify,
  errors as joseErrors,
  EmbeddedJWK,
} from "jose";
import type { Request, Response, NextFunction, Handler } from "express";

import {
  InsufficientScope,
  InvalidDpopProof,
  InvalidRequest,
  InvalidToken,
  Unauthorized,
  UseDpopNonce,
} from "./errors/errors.js";
import {
  validateIat,
  validateHtm,
  validateHtu,
  validateJwk,
  validateAth,
  validateJti,
  validateNonce,
  validateProofHeaders,
} from "./validations/dpop-proof-validations.js";
import { TOKEN_TYPE } from "./constants/constants.js";
import type {
  AuthMiddlewareOptions,
  ProtectRouteOptions,
} from "./types/types.js";
import type { DpopProofPayload } from "./types/types.internal.js";
import type { JWTPayload, JWSHeaderParameters, JWK } from "jose";

function buildJwksUri(authOptions: AuthMiddlewareOptions): URL {
  const { issuer, jwksUri } = authOptions;

  if (jwksUri) {
    return new URL(jwksUri);
  }

  return new URL("/.well-known/jwks.json", issuer);
}

function verifyAuthOptions(authOptions: AuthMiddlewareOptions): void {
  assert(authOptions.issuer, "'issuer' must be provided in options");
  assert(authOptions.audience, "'audience' must be provided in options");
  assert(authOptions.nonceSecret, "'nonceSecret' must be provided in options");
  assert(authOptions.nonceSecret.length !== 32, "'nonceSecret' must be 32 bytes");
}

async function verifyAccessToken({
  accessToken,
  jwks,
  authOptions,
}: {
  accessToken: string;
  jwks: ReturnType<typeof createRemoteJWKSet>;
  authOptions: AuthMiddlewareOptions;
}): Promise<{
  header: JWSHeaderParameters;
  payload: JWTPayload;
  accessToken: string;
}> {
  try {
    const { payload, protectedHeader } = await jwtVerify(accessToken, jwks, {
      issuer: authOptions.issuer,
      audience: authOptions.audience,
    });

    return {
      header: protectedHeader,
      payload,
      accessToken,
    };
  } catch (error) {
    if (error instanceof joseErrors.JWTExpired) {
      throw new InvalidToken(
        TOKEN_TYPE.BEARER,
        authOptions.audience,
        "The access token is expired",
      );
    }

    if (error instanceof joseErrors.JWTInvalid) {
      throw new InvalidToken(
        TOKEN_TYPE.BEARER,
        authOptions.audience,
        "The access token is invalid",
      );
    }

    // Throw a generic error
    throw new InvalidToken(
      TOKEN_TYPE.BEARER,
      authOptions.audience,
      "The access token is invalid",
    );
  }
}

async function verifyDpopProof(
  req: Request,
  res: Response,
  proof: string,
  authOptions: AuthMiddlewareOptions,
  token: string,
  jktFromAccessToken: string,
): Promise<void> {
  try {
    const { payload, protectedHeader } = await jwtVerify(
      proof as string,
      EmbeddedJWK,
    );
    const { htm, htu, ath, jti, nonce, iat } = payload as DpopProofPayload;

    validateProofHeaders(protectedHeader);
    await validateJwk(protectedHeader.jwk as JWK, jktFromAccessToken);
    validateIat(iat);
    validateHtm(req, htm);
    validateHtu(req, htu);
    await validateAth(token, ath);
    await validateNonce(nonce, ath, res, authOptions);

    await validateJti(jti, authOptions.jtiStore);
  } catch (e) {
    if (e instanceof UseDpopNonce) {
      throw e;
    }

    if (e instanceof Error) {
      throw new InvalidDpopProof(
        TOKEN_TYPE.DPOP,
        authOptions.audience,
        e.message,
      );
    }
  }
}

function isDpopVerificationRequired({
  authOptions,
  isDpopBoundToken,
  hasDpopAuthorizationHeader,
}: {
  authOptions: AuthMiddlewareOptions;
  isDpopBoundToken: boolean;
  hasDpopAuthorizationHeader: boolean;
}): boolean {
  const { enforceDPoP } = authOptions;

  if (enforceDPoP) {
    return true;
  }

  if (isDpopBoundToken) {
    return true;
  }

  if (hasDpopAuthorizationHeader) {
    return true;
  }

  return false;
}

export const authMiddleware = (authOptions: AuthMiddlewareOptions): Handler => {
  verifyAuthOptions(authOptions);

  const jwksUrl = buildJwksUri(authOptions);
  const jwks = createRemoteJWKSet(jwksUrl);

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { authorization } = req.headers;

      const hasBearerAuthorizationHeader =
        !!authorization?.startsWith("Bearer ");
      const hasDpopAuthorizationHeader = !!authorization?.startsWith("DPoP ");

      if (
        !authorization ||
        (!hasBearerAuthorizationHeader && !hasDpopAuthorizationHeader)
      ) {
        throw new Unauthorized(TOKEN_TYPE.BEARER, authOptions.audience);
      }

      const accessToken = authorization.split(" ")[1];

      if (!accessToken) {
        throw new Unauthorized(TOKEN_TYPE.BEARER, authOptions.audience);
      }

      const {
        header,
        payload,
        accessToken: verifiedAccessToken,
      } = await verifyAccessToken({
        accessToken,
        jwks,
        authOptions,
      });

      const isDpopBoundToken = !!(payload.cnf as { jkt?: string })?.jkt;

      const enforceDPoPVerification = isDpopVerificationRequired({
        authOptions,
        isDpopBoundToken,
        hasDpopAuthorizationHeader,
      });

      if (enforceDPoPVerification) {
        if (!isDpopBoundToken) {
          throw new InvalidToken(
            TOKEN_TYPE.DPOP,
            authOptions.audience,
            "The access token needs to be DPoP-bound",
          );
        }

        if (!hasDpopAuthorizationHeader) {
          throw new InvalidRequest(
            TOKEN_TYPE.BEARER,
            authOptions.audience,
            "DPoP-bound access tokens must be used with a DPoP authorization header",
          );
        }

        const { dpop: proof } = req.headers;

        if (!proof) {
          throw new InvalidRequest(
            TOKEN_TYPE.DPOP,
            authOptions.audience,
            "DPoP header is required when using DPoP token type",
          );
        }

        await verifyDpopProof(
          req,
          res,
          proof as string,
          authOptions,
          verifiedAccessToken,
          (payload.cnf as { jkt: string }).jkt,
        );
      }

      req.auth = {
        header,
        payload,
        token: verifiedAccessToken,
      };

      next();
    } catch (e) {
      if (e instanceof Unauthorized) {
        res
          .status(e.statusCode)
          .header("WWW-Authenticate", e.wwwAuthenticate)
          .end();
        return;
      }

      if (e instanceof UseDpopNonce) {
        res
          .status(e.statusCode)
          .header("WWW-Authenticate", e.wwwAuthenticate)
          .json({
            error: e.code,
            error_description: e.description,
          });
        return;
      }

      if (
        e instanceof InvalidToken ||
        e instanceof InsufficientScope ||
        e instanceof InvalidDpopProof ||
        e instanceof InvalidRequest
      ) {
        res
          .status(e.statusCode)
          .header("WWW-Authenticate", e.wwwAuthenticate)
          .json({
            error: e.code,
            error_description: e.description,
          });
        return;
      }

      res.status(500).json({
        error: "server_error",
        error_description: "There was an unknown error",
      });
      return;
    }
  };
};

export function protectRoute(
  options: ProtectRouteOptions = {},
): (req: Request, res: Response, next: NextFunction) => void {
  const { enforceDPoP = false, requiredScopes } = options;

  return (req, res, next) => {
    if (enforceDPoP && !req.auth?.payload?.cnf?.jkt) {
      return res.status(401).header("WWW-Authenticate", "DPoP").json({
        error: "invalid_token",
        error_description: "The access token needs to be DPoP-bound",
      });
    }

    if (!req.auth) {
      return res.status(401).header("WWW-Authenticate", "Bearer").end();
    }

    if (requiredScopes && Array.isArray(requiredScopes)) {
      const scope = req.auth?.payload?.scope;

      if (!scope || scope !== "string") {
        res.status(403).json({
          error: "insufficient_scope",
          error_description: "The access token has no scopes",
        });
      }

      const tokenScopes = (scope as string).split(" ");

      const hasAllScopes = requiredScopes.every((scope) =>
        tokenScopes.includes(scope),
      );

      if (!hasAllScopes) {
        res.status(403).json({
          error: "insufficient_scope",
          error_description: `Required scopes are: '${requiredScopes.join(" ")}'`,
        });
      }
    }

    next();
  };
}
