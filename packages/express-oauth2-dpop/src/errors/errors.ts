import { TOKEN_TYPE } from "../constants/constants.js";
import { TokenType } from "../types/types.internal.js";

export class Unauthorized extends Error {
  statusCode: number;
  wwwAuthenticate: string;

  constructor(tokenType: TokenType, audience: string) {
    super();
    this.statusCode = 401;
    this.wwwAuthenticate = `${tokenType} realm="${audience}"`;
  }
}

export class InvalidToken extends Error {
  statusCode: number;
  code: string;
  description: string;
  wwwAuthenticate: string;

  constructor(tokenType: TokenType, audience: string, description: string) {
    super();
    this.statusCode = 401;
    this.code = "invalid_token";
    this.description = description;
    this.wwwAuthenticate = `${tokenType} realm="${audience}" error="${this.code}", error_description="${this.description}"`;
  }
}

export class InvalidRequest extends Error {
  statusCode: number;
  code: string;
  description: string;
  wwwAuthenticate: string;

  constructor(tokenType: TokenType, audience: string, description: string) {
    super();
    this.statusCode = 400;
    this.code = "invalid_request";
    this.description = description;
    this.wwwAuthenticate = `${tokenType} realm="${audience}" error="${this.code}", error_description="${this.description}"`;
  }
}

export class InvalidDpopProof extends Error {
  statusCode: number;
  code: string;
  description: string;
  wwwAuthenticate: string;

  constructor(tokenType: TokenType, audience: string, description: string) {
    super();
    this.statusCode = 400;
    this.code = "invalid_dpop_proof";
    this.description = description;
    this.wwwAuthenticate = `${tokenType} realm="${audience}" error="${this.code}", error_description="${this.description}"`;
  }
}

export class UseDpopNonce extends Error {
  statusCode: number;
  code: string;
  description: string;
  wwwAuthenticate: string;

  constructor(description: string) {
    super();
    this.statusCode = 401;
    this.code = "use_dpop_nonce";
    this.description = description;
    this.wwwAuthenticate = `${TOKEN_TYPE.DPOP} error="${this.code}", error_description="${this.description}"`;
  }
}

export class InsufficientScope extends Error {
  statusCode: number;
  code: string;
  description: string;
  wwwAuthenticate: string;

  constructor(tokenType: TokenType, audience: string, description: string) {
    super();
    this.statusCode = 403;
    this.code = "insufficient_scope";
    this.description = description;
    this.wwwAuthenticate = `${tokenType} realm="${audience}" error="${this.code}", error_description="${this.description}"`;
  }
}
