import {
  createRemoteJWKSet,
  jwtVerify,
  errors as joseErrors,
  EmbeddedJWK,
} from "jose";
import type { Request, Response, NextFunction, Handler } from "express";
import type { JWTPayload, JWSHeaderParameters } from "jose";

import {
  InvalidDpopProof,
  InvalidRequest,
  InvalidToken,
  Unauthorized,
  UseDpopNonce,
} from "../errors/errors.js";
import {
  validateIat,
  validateHtm,
  validateHtu,
  validateJwk,
  validateAth,
  validateJti,
  validateNonce,
  validateProofHeaders,
} from "../validations/dpop-proof-validations.js";
import {
  assertAuthOptions,
  buildJwksUri,
  parseAuthorizationHeader,
} from "../utils/other-utils.js";
import { handleError } from "../utils/error-utils.js";
import { TOKEN_TYPE } from "../constants/constants.js";
import type {
  AuthMiddlewareOptions,
  BoundAccessToken,
} from "../types/types.js";
import type { DpopProofPayload } from "../types/types.internal.js";

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
  payload: JWTPayload & Partial<BoundAccessToken>;
  accessToken: string;
}> {
  try {
    const { payload, protectedHeader } = await jwtVerify<
      Partial<BoundAccessToken>
    >(accessToken, jwks, {
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
        "The access token is expired"
      );
    }

    throw new InvalidToken(
      TOKEN_TYPE.BEARER,
      authOptions.audience,
      "The access token is invalid"
    );
  }
}

async function verifyDpopProof(
  req: Request,
  res: Response,
  proof: string,
  authOptions: AuthMiddlewareOptions,
  token: string,
  jktFromAccessToken: string
): Promise<void> {
  try {
    const { payload, protectedHeader } = await jwtVerify<DpopProofPayload>(
      proof as string,
      EmbeddedJWK
    );
    const { htm, htu, ath, jti, nonce, iat } = payload;

    validateProofHeaders(protectedHeader);
    await validateJwk(protectedHeader.jwk!, jktFromAccessToken);
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
        e.message
      );
    }
  }
}

export const authMiddleware = (authOptions: AuthMiddlewareOptions): Handler => {
  assertAuthOptions(authOptions);

  const jwksUrl = buildJwksUri(authOptions);
  const jwks = createRemoteJWKSet(jwksUrl);

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const authorization = parseAuthorizationHeader(req.headers.authorization);

      if (!authorization) {
        throw new Unauthorized(TOKEN_TYPE.BEARER, authOptions.audience);
      }

      const { type: authType, accessToken } = authorization;

      const {
        header,
        payload,
        accessToken: verifiedAccessToken,
      } = await verifyAccessToken({
        accessToken,
        jwks,
        authOptions,
      });

      const isDpopBoundToken = !!payload.cnf?.jkt;
      const shouldVerifyDpop =
        authOptions.enforceDPoP ||
        isDpopBoundToken ||
        authType === TOKEN_TYPE.DPOP;

      if (shouldVerifyDpop) {
        if (!isDpopBoundToken) {
          throw new InvalidToken(
            TOKEN_TYPE.DPOP,
            authOptions.audience,
            "The access token needs to be DPoP-bound"
          );
        }

        if (authType !== TOKEN_TYPE.DPOP) {
          throw new InvalidRequest(
            TOKEN_TYPE.BEARER,
            authOptions.audience,
            "DPoP-bound access tokens must be used with a DPoP authorization header"
          );
        }

        const { dpop: proof } = req.headers;

        if (!proof || typeof proof !== "string") {
          throw new InvalidRequest(
            TOKEN_TYPE.DPOP,
            authOptions.audience,
            "DPoP header is required when using DPoP token type"
          );
        }

        await verifyDpopProof(
          req,
          res,
          proof,
          authOptions,
          verifiedAccessToken,
          payload.cnf!.jkt
        );
      }

      req.auth = {
        header,
        payload,
        token: verifiedAccessToken,
      };

      next();
    } catch (e) {
      handleError(e, res);
    }
  };
};
