import { TOKEN_TYPE } from "../constants/constants.js";

export type TokenType = (typeof TOKEN_TYPE)[keyof typeof TOKEN_TYPE];

export type DpopProofPayload = {
  /**
   * The issue time of the DPoP proof.
   */
  iat?: number;
  /**
   * The HTTP method used in the request.
   * Must match the method of the request being authenticated.
   */
  htm?: string;
  /**
   * The HTTP URL of the request being authenticated.
   * Must match the URL of the request being authenticated.
   */
  htu?: string;
  /**
   * The Access Token Hash (ath) is a hash of the access token.
   * Must match the hash of the access token used in the request.
   */
  ath?: string;
  /**
   * JWT ID (jti) is a unique identifier for the DPoP proof to prevent replay attacks.
   * Must be unique for each DPoP proof.
   */
  jti?: string;
  /**
   * Nonce provided by the resource server to enforce freshness or ordering.
   */
  nonce?: string;
};

export type NonceData = {
  /**
   * The issue time of the nonce.
   */
  iat: number;
  /**
   * The expiration time of the nonce
   */
  exp: number;
  /**
   * Hash of the access token.
   */
  ath?: string;
};

export type ParsedAuthorizationHeaders = null | {
  type: TokenType;
  accessToken: string;
};
