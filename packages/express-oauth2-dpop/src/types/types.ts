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

export type AuthPayload = JWTPayload & Partial<BoundAccessToken>;

export type AuthResult = {
  header: JWSHeaderParameters;
  payload: AuthPayload;
  token: string;
};

/* eslint-disable @typescript-eslint/no-namespace */
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
  protectRoute?: boolean;
  /**
   * If true, the middleware will require a DPoP-bound access token in all routes.
   * If false, it will accept both Bearer and DPoP tokens.
   * @default false
   */
  enforceDPoP?: boolean;
  jtiStore: AbstractJtiStore;
};

export interface ProtectRouteOptions {
  /**
   * If true, the middleware will require a DPoP-bound access token in all routes.
   * If false, it will accept both Bearer and DPoP tokens.
   * @default false
   */
  enforceDPoP?: boolean;
  requiredScopes?: string[];
}

export type JtiData = {
  expiresAt: number;
};
