import { describe, test, expect } from "vitest";
import crypto from "crypto";

import {
  buildJwksUri,
  assertAuthOptions,
  parseAuthorizationHeader,
} from "../../../utils/other-utils.js";
import { TOKEN_TYPE } from "../../../constants/constants.js";
import { AuthMiddlewareOptions } from "../../../types/types.js";
import { MockJtiStore } from "../../mocks/jti-store-mock.test.js";

describe("other-utils", () => {
  const mockNonceSecret = crypto.randomBytes(32).toString("hex");

  describe("buildJwksUri", () => {
    test("should return jwksUri if provided", () => {
      const options = {
        issuer: "https://example.com/",
        jwksUri: "https://custom-jwks.com/jwks.json",
      };
      const result = buildJwksUri(options as AuthMiddlewareOptions);
      expect(result.href).toBe("https://custom-jwks.com/jwks.json");
    });

    test("should return default JWKS URI based on issuer", () => {
      const options = {
        issuer: "https://example.com/",
        jwksUri: undefined,
      };
      const result = buildJwksUri(options as AuthMiddlewareOptions);
      expect(result.href).toBe("https://example.com/.well-known/jwks.json");
    });

    test("should handle issuer without trailing slash", () => {
      const options = {
        issuer: "https://example.com",
      };
      const result = buildJwksUri(options as AuthMiddlewareOptions);
      expect(result.href).toBe("https://example.com/.well-known/jwks.json");
    });
  });

  describe("assertAuthOptions", () => {
    const baseOptions = {
      issuer: "https://example.com/",
      audience: "api",
      nonceSecret: mockNonceSecret,
      jtiStore: new MockJtiStore(),
    };

    test("does not throw with valid options", () => {
      expect(() => assertAuthOptions(baseOptions)).not.toThrow();
    });

    test("throws if issuer is missing", () => {
      const options = { ...baseOptions, issuer: undefined };
      // @ts-expect-error - Invalid options
      expect(() => assertAuthOptions(options)).toThrow(
        "'issuer' must be provided in options"
      );
    });

    test("throws if audience is missing", () => {
      const options = { ...baseOptions, audience: undefined };
      // @ts-expect-error - Invalid options
      expect(() => assertAuthOptions(options)).toThrow(
        "'audience' must be provided in options"
      );
    });

    test("throws if nonceSecret is missing", () => {
      const options = { ...baseOptions, nonceSecret: undefined };
      // @ts-expect-error - Invalid options
      expect(() => assertAuthOptions(options)).toThrow(
        "'nonceSecret' must be provided in options"
      );
    });

    test("throws if nonceSecret length is not 32 bytes hex", () => {
      const options = {
        ...baseOptions,
        nonceSecret: crypto.randomBytes(24).toString("hex"),
      };
      expect(() => assertAuthOptions(options)).toThrow(
        "'nonceSecret' must be 32 bytes"
      );
    });
  });

  describe("parseAuthorizationHeader", () => {
    test("returns null if authorization is undefined", () => {
      expect(parseAuthorizationHeader(undefined)).toBeNull();
    });

    test("parses Bearer token", () => {
      const tokenType = TOKEN_TYPE.BEARER;
      const accessToken = "my-access-token";

      const header = `${tokenType} ${accessToken}`;

      const parsed = parseAuthorizationHeader(header);

      expect(parsed).toEqual({
        type: tokenType,
        accessToken,
      });
    });

    test("parses DPoP token", () => {
      const tokenType = TOKEN_TYPE.DPOP;
      const accessToken = "my-access-token";

      const header = `${tokenType} ${accessToken}`;

      const parsed = parseAuthorizationHeader(header);

      expect(parsed).toEqual({
        type: tokenType,
        accessToken,
      });
    });

    test("returns null if unknown token type", () => {
      const header = "Unknown token";
      expect(parseAuthorizationHeader(header)).toBeNull();
    });

    test("returns null if missing token", () => {
      const header = "Bearer";
      expect(parseAuthorizationHeader(header)).toBeNull();
    });
  });
});
