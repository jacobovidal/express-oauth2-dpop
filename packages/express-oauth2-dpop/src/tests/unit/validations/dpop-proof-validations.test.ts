import { describe, test, expect, vi, afterEach, beforeEach } from "vitest";
import type { Request, Response } from "express";
import crypto from "crypto";
import * as jose from "jose";

import {
  validateProofHeaders,
  validateIat,
  validateHtm,
  validateHtu,
  validateJwk,
  validateAth,
  validateJti,
  validateNonce,
} from "../../../validations/dpop-proof-validations.js";
import * as nonceUtils from "../../../utils/nonce-utils.js";
import { MockJtiStore } from "../../../tests/mocks/jti-store-mock.test.js";
import { UseDpopNonce } from "../../../errors/errors.js";
import type { AuthMiddlewareOptions } from "../../..//types/types.js";

describe("dpop-validator", () => {
  vi.mock("jose", async () => {
    const actual = await vi.importActual("jose");
    return {
      ...actual,
      calculateJwkThumbprint: vi.fn(),
    };
  });

  const mockedCalculateJwkThumbprint =
    jose.calculateJwkThumbprint as unknown as ReturnType<typeof vi.fn>;

  describe("validateProofHeaders", () => {
    test("throws if typ header is missing or incorrect", () => {
      // @ts-expect-error - Invalid headers
      expect(() => validateProofHeaders({})).toThrow(
        "DPoP 'typ' header must be 'dpop+jwt'"
      );

      expect(() =>
        // @ts-expect-error - Invalid headers
        validateProofHeaders({ typ: "wrong" })
      ).toThrow("DPoP 'typ' header must be 'dpop+jwt'");
    });

    test("does not throw for valid typ header", () => {
      expect(() =>
        validateProofHeaders({ typ: "dpop+jwt", alg: "ES256" })
      ).not.toThrow();
    });
  });

  describe("validateIat", () => {
    const now = Math.floor(Date.now() / 1000);
    const IAT_LEEWAY = 30;

    test("throws if iat is missing", () => {
      expect(() => validateIat(undefined)).toThrow(
        "DPoP 'iat' claim is required"
      );
    });

    test("throws if iat is outside acceptable range", () => {
      expect(() => validateIat(now - IAT_LEEWAY - 1)).toThrow(
        "DPoP 'iat' is not within acceptable time range"
      );

      expect(() => validateIat(now + IAT_LEEWAY + 1)).toThrow(
        "DPoP 'iat' is not within acceptable time range"
      );
    });

    test("does not throw if iat is within range", () => {
      expect(() => validateIat(now)).not.toThrow();
      expect(() => validateIat(now - IAT_LEEWAY)).not.toThrow();
      expect(() => validateIat(now + IAT_LEEWAY)).not.toThrow();
    });
  });

  describe("validateHtm", () => {
    const mockReq = { method: "GET" } as Request;
    const mockReqWithCaseInsensitiveMethod = { method: "post" } as Request;

    test("throws if htm is missing", () => {
      expect(() => validateHtm(mockReq, undefined)).toThrow(
        "DPoP 'htm' claim is required"
      );
    });

    test("throws if htm does not match request method", () => {
      expect(() => validateHtm(mockReq, "POST")).toThrow(
        "DPoP 'htm' mismatch: expected 'GET', got 'POST'"
      );
    });

    test("does not throw if htm matches request method (case-insensitive)", () => {
      expect(() => validateHtm(mockReq, "GET")).not.toThrow();
      expect(() =>
        validateHtm(mockReqWithCaseInsensitiveMethod, "POST")
      ).not.toThrow();
    });
  });

  describe("validateHtu", () => {
    const mockReq = {
      protocol: "https",
      get: vi.fn().mockReturnValue("example.com"),
      originalUrl: "/foo/bar?baz=qux",
    } as unknown as Request;

    test("throws if htu is missing", () => {
      expect(() => validateHtu(mockReq, undefined)).toThrow(
        "DPoP 'htu' claim is required"
      );
    });

    test("throws if htu does not match full request URL without query", () => {
      const expectedUrl = "https://example.com/foo/bar";

      expect(() => validateHtu(mockReq, "https://example.com/other")).toThrow(
        `DPoP 'htu' mismatch: expected "${expectedUrl}", got "https://example.com/other"`
      );
    });

    test("does not throw if htu matches full request URL without query", () => {
      const expectedUrl = "https://example.com/foo/bar";

      expect(() => validateHtu(mockReq, expectedUrl)).not.toThrow();
    });
  });

  describe("validateJwk", async () => {
    afterEach(() => {
      vi.clearAllMocks();
    });

    test("throws if jkt does not match jwk thumbprint", async () => {
      const jwk = { kty: "oct", k: "abc" } as jose.JWK;

      mockedCalculateJwkThumbprint.mockResolvedValueOnce("thumbprint");

      await expect(validateJwk(jwk, "differentThumbprint")).rejects.toThrow(
        "DPoP 'jkt' mismatch"
      );
    });

    test("does not throw if jkt matches thumbprint", async () => {
      const jwk = { kty: "oct", k: "abc" } as jose.JWK;

      mockedCalculateJwkThumbprint.mockResolvedValueOnce("matchThumbprint");

      await expect(validateJwk(jwk, "matchThumbprint")).resolves.not.toThrow();
    });
  });

  describe("validateAth", () => {
    test("throws if ath is missing", async () => {
      await expect(validateAth("token", undefined)).rejects.toThrow(
        "DPoP 'ath' claim is required"
      );
    });

    test("throws if ath does not match token hash", async () => {
      const wrongAth = "wrongAth";

      await expect(validateAth("token", wrongAth)).rejects.toThrow(
        "DPoP 'ath' mismatch"
      );
    });

    test("does not throw if ath matches token hash", async () => {
      const token = "token";
      const digest = crypto.createHash("sha256").update(token).digest();
      const expectedAth = jose.base64url.encode(digest);

      await expect(validateAth(token, expectedAth)).resolves.not.toThrow();
    });
  });

  describe("validateJti", () => {
    let jtiStore: MockJtiStore;

    beforeEach(() => {
      jtiStore = new MockJtiStore();
    });

    test("throws if jti is missing", async () => {
      await expect(validateJti(undefined, jtiStore)).rejects.toThrow(
        "DPoP 'jti' claim is required"
      );
    });

    test("throws if jti already exists in the store", async () => {
      const jti = "used-jti";

      await validateJti(jti, jtiStore);

      await expect(validateJti(jti, jtiStore)).rejects.toThrow(
        "DPoP 'jti' has already been used"
      );
    });

    test("sets jti with expiresAt timestamp if jti does not exist", async () => {
      const jti = "new-jti";

      const doesNotExist = await jtiStore.get(jti);
      expect(doesNotExist).toBeUndefined();

      await validateJti(jti, jtiStore);

      const stored = await jtiStore.get(jti);
      expect(stored).toBeDefined();
    });
  });

  describe("validateNonce", () => {
    const mockAuthOptions = {
      nonceSecret: "nonce-secret",
    } as unknown as AuthMiddlewareOptions;
    const mockRes = {
      setHeader: vi.fn(),
    } as unknown as Response;

    beforeEach(() => {
      vi.restoreAllMocks();
    });

    test("throws UseDpopNonce and returns DPoP-Nonce header if nonce is missing", async () => {
      vi.spyOn(nonceUtils, "createStatelessNonce").mockResolvedValue(
        "new-nonce"
      );

      await expect(
        validateNonce(undefined, "ath-value", mockRes, mockAuthOptions)
      ).rejects.toThrow(UseDpopNonce);

      expect(mockRes.setHeader).toHaveBeenCalledWith("DPoP-Nonce", "new-nonce");
    });

    test("throws UseDpopNonce and returns DPoP-Nonce header if token ath does not match nonce ath", async () => {
      vi.spyOn(nonceUtils, "createStatelessNonce").mockResolvedValue("new-nonce");

      const now = Math.floor(Date.now() / 1000);

      vi.spyOn(nonceUtils, "decryptStatelessNonce").mockResolvedValue({
        iat: now - 30,
        ath: "different-ath",
        exp: now + 120,
      });

      await expect(validateNonce("some-nonce", "ath-value", mockRes, mockAuthOptions)).rejects.toThrow(UseDpopNonce);

      expect(mockRes.setHeader).toHaveBeenCalledWith("DPoP-Nonce", "new-nonce");
    });

    test("returns DPoP-Nonce header if nonce exp is less than 60 seconds", async () => {
      vi.spyOn(nonceUtils, "createStatelessNonce").mockResolvedValue("new-nonce");

      const now = Math.floor(Date.now() / 1000);

      vi.spyOn(nonceUtils, "decryptStatelessNonce").mockResolvedValue({
        iat: now - 30,
        ath: "ath-value",
        exp: now + 30,
      });

      await expect(validateNonce("some-nonce", "ath-value", mockRes, mockAuthOptions)).resolves.not.toThrow();

      expect(mockRes.setHeader).toHaveBeenCalledWith("DPoP-Nonce", "new-nonce");
    });

    test("does not set header and does not throw if nonce is valid and not expiring soon", async () => {
      vi.spyOn(nonceUtils, "createStatelessNonce").mockResolvedValue("new-nonce");

      const now = Math.floor(Date.now() / 1000);

      vi.spyOn(nonceUtils, "decryptStatelessNonce").mockResolvedValue({
        iat: now - 30,
        ath: "ath-value",
        exp: now + 120,
      });

      await expect(validateNonce("some-nonce", "ath-value", mockRes, mockAuthOptions)).resolves.not.toThrow();

      expect(mockRes.setHeader).not.toHaveBeenCalled();
    });

    test("throws UseDpopNonce and sets header if decryptStatelessNonce throws", async () => {
      vi.spyOn(nonceUtils, "createStatelessNonce").mockResolvedValue("new-nonce");

      vi.spyOn(nonceUtils, "decryptStatelessNonce").mockRejectedValue(new Error());

      await expect(validateNonce("invalid-nonce", "ath-value", mockRes, mockAuthOptions)).rejects.toThrow(UseDpopNonce);

      expect(mockRes.setHeader).toHaveBeenCalledWith("DPoP-Nonce", "new-nonce");
    });
  });
});
