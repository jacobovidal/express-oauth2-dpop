import type { JWSHeaderParameters, JWTPayload } from "jose";

import type { AbstractJtiStore } from "../store/abstract-jti-store.js";

export type BoundAccessToken = {
  /**
   * Confirmation claim that holds the JWK thumbprint.
   */
  cnf: {
    /**
     * JWK SHA-256 thumbprint of the key used in the DPoP proof.
     */
    jkt: string;
  };
};

/**
 * The result of a successfully verified access token.
 */
export type AuthResult = {
  /**
   * The decoded JWS header of the access token.
   */
  header: JWSHeaderParameters;
  /**
   * The decoded payload of the access token.
   */
  payload: JWTPayload & Partial<BoundAccessToken>;
  /**
   * The original raw JWT string.
   */
  token: string;
};

/* eslint-disable @typescript-eslint/no-namespace */
/**
 * Extends Express's Request interface to optionally include `auth`,
 * which contains the parsed and validated access token.
 */
declare global {
  namespace Express {
    interface Request {
      auth?: AuthResult;
    }
  }
}
/* eslint-enable @typescript-eslint/no-namespace */

export type AuthMiddlewareOptions = {
  /**
   * The issuer of the access token.
   * @example
   * "https://auth.example.com"
   */
  issuer: string;

  /**
   * The audience for which the access token is intended.
   * @example
   * "https://api.example.com"
   */
  audience: string;

  /**
   * The URL to the JWKS endpoint.
   * If not provided, it will default to `{{issuer}}/.well-known/jwks.json`.
   * @default {{issuer}}/.well-known/jwks.json
   * @example
   * "https://auth.example.com/.well-known/jwks.json"
   */
  jwksUri?: string;

  /**
   * If true, the middleware will automatically protect all routes.
   * If false, routes must be protected manually using `protectRoute()` middleware.
   * @default true
   */
  protectRoutes?: boolean;

  /**
   * If true, the middleware will require a DPoP-bound access token in all protected routes.
   * If false, it will accept both Bearer and DPoP tokens.
   * @default false
   */
  enforceDPoP?: boolean;

  /**
   * A secret string used to encrypt and decrypt stateless nonces (JWE).
   * The string is hashed with SHA-256 to derive a consistent 32-byte encryption key.
   *
   * This secret should be cryptographically secure and remain consistent
   * across server restarts to allow decrypting issued nonces.
   *
   * @example
   * "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
   *
   * @remarks
   * Generate a secure secret with:
   * `openssl rand -hex 32`
   */
  nonceSecret: string;

  /**
   * Store implementation used to track used JWT IDs (`jti`) and prevent replay attacks.
   */
  jtiStore: AbstractJtiStore;
};

export type ProtectRouteOptions = {
  /**
   * If true, the middleware will require a DPoP-bound access token in all routes.
   * If false, it will accept both Bearer and DPoP tokens.
   * @default false
   */
  enforceDPoP?: boolean;
  
  /**
   * List of required scopes for the protected route.
   * If provided, the access token must include **at least** all listed scopes.
   * Additional scopes in the token are allowed.
   * If not provided, no scope validation will be performed.
   *
   * @example
   * ["read:profile", "write:profile"]
   */
  scope?: string[];
};

/**
 * Metadata for a stored `jti`, used to prevent DPoP proof replay attacks.
 */
export type JtiData = {
  /**
   * The time (in seconds since epoch) when this `jti` expires and can be removed from the store.
   *
   * @example
   * 1750113600
   */
  expiresAt: number;
};
