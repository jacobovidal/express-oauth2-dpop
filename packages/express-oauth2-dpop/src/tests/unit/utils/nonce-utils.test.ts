import { describe, test, expect } from "vitest";
import crypto from "crypto";
import { EncryptJWT } from "jose";

import {
  createStatelessNonce,
  decryptStatelessNonce,
  deriveAesGcmKeyFromNonceSecret,
  NONCE_EXPIRATION,
} from "../../../utils/nonce-utils.js";
import { AuthMiddlewareOptions } from "../../../types/types.js";
import { MockJtiStore } from "../../mocks/jti-store-mock.test.js";

describe("nonce-utils", () => {
  const mockNonceSecret = crypto.randomBytes(32).toString("hex");
  const mockAth = "cqdoXmRreKgQeXXpRtg4QAi0Ik46wkpVdGMyTr_HmpM";
  const mockAuthOptions: AuthMiddlewareOptions = {
    issuer: "https://auth.exapmle.com",
    audience: "api",
    nonceSecret: mockNonceSecret,
    jtiStore: new MockJtiStore(),
  };

  describe("deriveAesGcmKeyFromNonceSecret", async () => {
    test("should generate a valid AES-GCM key based on a 32 bytes secret", async () => {
      const cryptoKey = await deriveAesGcmKeyFromNonceSecret(mockNonceSecret);

      console.log("cryptoKey", cryptoKey);
      expect(cryptoKey.type).toBe("secret");
      expect(cryptoKey.extractable).toBeFalsy();
      expect(cryptoKey.algorithm.name).toBe("AES-GCM");
      expect(cryptoKey.algorithm.length).toBe(256);
    });

    test("should return same key for same secret", async () => {
      const key1 = await deriveAesGcmKeyFromNonceSecret(mockNonceSecret);
      const key2 = await deriveAesGcmKeyFromNonceSecret(mockNonceSecret);

      expect(key1).toEqual(key2);
    });
  });

  describe("createStatelessNonce", () => {
    test("should create a stateless nonce that can be decrypted correctly", async () => {
      const generatedNonce = await createStatelessNonce(
        mockAth,
        mockAuthOptions,
      );

      expect(typeof generatedNonce).toBe("string");
      expect(generatedNonce.split(".").length).toBe(5); // JWE format (compact serialization)

      const decrypted = await decryptStatelessNonce(
        generatedNonce,
        mockAuthOptions,
      );
      expect(decrypted.ath).toBe(mockAth);
      expect(typeof decrypted.iat).toBe("number");
      expect(typeof decrypted.exp).toBe("number");
    });

    test("should fail to decrypt with a different secret", async () => {
      const generatedNonce = await createStatelessNonce(
        mockAth,
        mockAuthOptions,
      );

      const wrongOptions = {
        ...mockAuthOptions,
        nonceSecret: crypto.randomBytes(32).toString("hex"), // different secret
      };

      await expect(
        decryptStatelessNonce(generatedNonce, wrongOptions),
      ).rejects.toThrow();
    });
  });

  describe("decryptStatelessNonce", () => {
    test("should decrypt a stateless nonce correctly", async () => {
      const nonce = await createStatelessNonce(mockAth, mockAuthOptions);
      const decrypted = await decryptStatelessNonce(nonce, mockAuthOptions);

      expect(decrypted.ath).toBe(mockAth);
      expect(typeof decrypted.exp).toBe("number");
      expect(typeof decrypted.iat).toBe("number");
    });

    test("should throw on malformed nonce", async () => {
      const malformedNonce = "this.is.not.a.valid.nonce";

      await expect(
        decryptStatelessNonce(malformedNonce, mockAuthOptions),
      ).rejects.toThrow();
    });

    test("should throw on expired nonce", async () => {
      const secretKey = await deriveAesGcmKeyFromNonceSecret(mockNonceSecret);

      const exp = Math.floor(Date.now() / 1000) - NONCE_EXPIRATION - 10;

      const expiringNonce = await new EncryptJWT({ ath: mockAth })
        .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
        .setIssuedAt()
        .setExpirationTime(exp)
        .encrypt(secretKey);

      await expect(
        decryptStatelessNonce(expiringNonce, mockAuthOptions),
      ).rejects.toThrow('"exp" claim timestamp check failed');
    });
  });
});
