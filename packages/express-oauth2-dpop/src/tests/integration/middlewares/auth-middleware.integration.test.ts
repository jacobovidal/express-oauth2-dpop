import { afterAll, beforeAll, describe, expect, test } from "vitest";
import nock from "nock";
import request from "supertest";
import { DPoPGenerateProofConfig, DPoPUtils } from "oauth-fetch";

import { DEFAULT_AUDIENCE, setupApi } from "../setup-api.js";
import { setupJwks } from "../setup-jwks.js";
import { generateAccessToken } from "../utils.js";

describe("auth-middleware", async () => {
  const dpopKeyPair = await DPoPUtils.generateKeyPair();
  const mockJkt = await DPoPUtils.calculateJwkThumbprint(dpopKeyPair.publicKey);

  beforeAll(() => {
    setupJwks();
  });

  afterAll(() => {
    nock.cleanAll();
    nock.restore();
  });

  describe("authMiddleware() options", () => {
    describe("protectRoutes: false", () => {
      const app = setupApi({ protectRoutes: false });

      test("allow access to a public route defined before authMiddleware()", async () => {
        await request(app)
          .get("/public/hello")
          .expect(200, { message: "Hello from public endpoint!" });
      });

      test("allow access to a public route defined after authMiddleware()", async () => {
        await request(app)
          .get("/private/hello")
          .expect(200, { message: "Hello from private endpoint!" });
      });
    });

    describe("protectRoutes: true", () => {
      const app = setupApi({ protectRoutes: true });

      test("deny access to a route defined after authMiddleware()", async () => {
        await request(app).get("/private/hello").expect(401);
      });

      test("allow access to a protected route using a valid Bearer token", async () => {
        const accessToken = await generateAccessToken();

        await request(app)
          .get("/private/hello")
          .set("Authorization", `Bearer ${accessToken}`)
          .expect(200, { message: "Hello from private endpoint!" });
      });
    });

    describe("enforceDPoP: false", () => {
      const app = setupApi({ enforceDPoP: false });

      test("allow access with valid Bearer token", async () => {
        const accessToken = await generateAccessToken();

        await request(app)
          .get("/private/hello")
          .set("Authorization", `Bearer ${accessToken}`)
          .expect(200, { message: "Hello from private endpoint!" });
      });
    });

    describe("enforceDPoP: true", () => {
      const app = setupApi({ enforceDPoP: true });

      test("deny access when token is not DPoP-bound", async () => {
        const accessToken = await generateAccessToken();

        await request(app)
          .get("/private/hello")
          .set("Authorization", `Bearer ${accessToken}`)
          .expect(401, {
            error: "invalid_token",
            error_description: "The access token needs to be DPoP-bound",
          });
      });

      test("allow access with valid DPoP-bound token", async () => {
        const accessToken = await generateAccessToken({
          jkt: mockJkt,
        });

        const proofPayload: DPoPGenerateProofConfig = {
          url: new URL(`http://${DEFAULT_AUDIENCE}/private/hello`),
          method: "GET",
          dpopKeyPair,
          accessToken,
        };

        const proof = await DPoPUtils.generateProof(proofPayload);

        const response = await request(app)
          .get("/private/hello")
          .set("Authorization", `DPoP ${accessToken}`)
          .set("DPoP", proof)
          .set("Host", DEFAULT_AUDIENCE)
          .expect(401, {
            error: "use_dpop_nonce",
            error_description: "DPoP 'nonce' claim is required",
          });

        const nonce = response.headers["dpop-nonce"];

        const proofWithNonce = await DPoPUtils.generateProof({
          ...proofPayload,
          nonce,
        });

        await request(app)
          .get("/private/hello")
          .set("Authorization", `DPoP ${accessToken}`)
          .set("DPoP", proofWithNonce)
          .set("Host", DEFAULT_AUDIENCE)
          .expect(200, { message: "Hello from private endpoint!" });
      });
    });
  });

  describe("endpoints", () => {
    const app = setupApi({ protectRoutes: false });

    describe("DPoP-protected", () => {
      test("allow access with valid token and nonce", async () => {
        const accessToken = await generateAccessToken({
          jkt: mockJkt,
        });

        const proofPayload: DPoPGenerateProofConfig = {
          url: new URL(`http://${DEFAULT_AUDIENCE}/private/dpop`),
          method: "GET",
          dpopKeyPair,
          accessToken,
        };

        const proof = await DPoPUtils.generateProof(proofPayload);

        const response = await request(app)
          .get("/private/dpop")
          .set("Authorization", `DPoP ${accessToken}`)
          .set("DPoP", proof)
          .set("Host", DEFAULT_AUDIENCE)
          .expect(401, {
            error: "use_dpop_nonce",
            error_description: "DPoP 'nonce' claim is required",
          });

        const nonce = response.headers["dpop-nonce"];

        const proofWithNonce = await DPoPUtils.generateProof({
          ...proofPayload,
          nonce,
        });

        await request(app)
          .get("/private/dpop")
          .set("Authorization", `DPoP ${accessToken}`)
          .set("DPoP", proofWithNonce)
          .set("Host", DEFAULT_AUDIENCE)
          .expect(200, { message: "Hello from DPoP-protected endpoint!" });
      });

      test("deny access with invalid nonce", async () => {
        const accessToken = await generateAccessToken({
          jkt: mockJkt,
        });

        const proofPayload: DPoPGenerateProofConfig = {
          url: new URL(`http://${DEFAULT_AUDIENCE}/private/dpop`),
          method: "GET",
          dpopKeyPair,
          accessToken,
          nonce: "invalid-nonce",
        };

        const proof = await DPoPUtils.generateProof(proofPayload);

        const response = await request(app)
          .get("/private/dpop")
          .set("Authorization", `DPoP ${accessToken}`)
          .set("DPoP", proof)
          .set("Host", DEFAULT_AUDIENCE)
          .expect(401, {
            error: "use_dpop_nonce",
            error_description: "DPoP 'nonce' is not valid",
          });

        const nonce = response.headers["dpop-nonce"];

        expect(nonce).toBeDefined();
      });

      test("deny access with invalid jkt", async () => {
        const accessToken = await generateAccessToken({
          jkt: "invalid-jkt",
        });

        const proofPayload: DPoPGenerateProofConfig = {
          url: new URL(`http://${DEFAULT_AUDIENCE}/private/dpop`),
          method: "GET",
          dpopKeyPair,
          accessToken,
        };

        const proof = await DPoPUtils.generateProof(proofPayload);

        await request(app)
          .get("/private/dpop")
          .set("Authorization", `DPoP ${accessToken}`)
          .set("DPoP", proof)
          .set("Host", DEFAULT_AUDIENCE)
          .expect(400, {
            error: "invalid_dpop_proof",
            error_description: `DPoP 'jkt' mismatch: expected '${mockJkt}', got 'invalid-jkt'`,
          });
      });

      test("deny access with invalid DPoP header", async () => {
        const accessToken = await generateAccessToken({
          jkt: mockJkt,
        });

        await request(app)
          .get("/private/dpop")
          .set("Authorization", `DPoP ${accessToken}`)
          .set("DPoP", "invalid-value")
          .set("Host", DEFAULT_AUDIENCE)
          .expect(400, {
            error: "invalid_dpop_proof",
            error_description: "Invalid Compact JWS",
          });
      });

      test("deny access with already used jti", async () => {
        const accessToken = await generateAccessToken({
          jkt: mockJkt,
        });

        const proofPayload: DPoPGenerateProofConfig = {
          url: new URL(`http://${DEFAULT_AUDIENCE}/private/dpop`),
          method: "GET",
          dpopKeyPair,
          accessToken,
        };

        const proof = await DPoPUtils.generateProof(proofPayload);

        const response = await request(app)
          .get("/private/dpop")
          .set("Authorization", `DPoP ${accessToken}`)
          .set("DPoP", proof)
          .set("Host", DEFAULT_AUDIENCE)
          .expect(401, {
            error: "use_dpop_nonce",
            error_description: "DPoP 'nonce' claim is required",
          });

        const nonce = response.headers["dpop-nonce"];

        const proofWithNonce = await DPoPUtils.generateProof({
          ...proofPayload,
          nonce,
        });

        await request(app)
          .get("/private/dpop")
          .set("Authorization", `DPoP ${accessToken}`)
          .set("DPoP", proofWithNonce)
          .set("Host", DEFAULT_AUDIENCE)
          .expect(200, { message: "Hello from DPoP-protected endpoint!" });

        // Replay attack
        await request(app)
          .get("/private/dpop")
          .set("Authorization", `DPoP ${accessToken}`)
          .set("DPoP", proofWithNonce)
          .set("Host", DEFAULT_AUDIENCE)
          .expect(400, {
            error: "invalid_dpop_proof",
            error_description: "DPoP 'jti' has already been used",
          });
      });

      test("deny access when missing nonce value", async () => {
        const accessToken = await generateAccessToken({
          jkt: mockJkt,
        });

        const proofPayload: DPoPGenerateProofConfig = {
          url: new URL(`http://${DEFAULT_AUDIENCE}/private/dpop`),
          method: "GET",
          dpopKeyPair,
          accessToken,
        };

        const proof = await DPoPUtils.generateProof(proofPayload);

        const response = await request(app)
          .get("/private/dpop")
          .set("Authorization", `DPoP ${accessToken}`)
          .set("DPoP", proof)
          .set("Host", DEFAULT_AUDIENCE)
          .expect(401, {
            error: "use_dpop_nonce",
            error_description: "DPoP 'nonce' claim is required",
          });

        const nonce = response.headers["dpop-nonce"];

        expect(nonce).toBeDefined();
      });
    });

    describe("Bearer-protected", () => {
      test("allow access with valid token", async () => {
        const accessToken = await generateAccessToken();

        await request(app)
          .get("/private/bearer")
          .set("Authorization", `Bearer ${accessToken}`)
          .expect(200, { message: "Hello from Bearer-protected endpoint!" });
      });

      test("deny access when using DPoP-bound access token", async () => {
        const accessToken = await generateAccessToken({
          jkt: mockJkt,
        });

        await request(app)
          .get("/private/bearer")
          .set("Authorization", `Bearer ${accessToken}`)
          .set("Host", DEFAULT_AUDIENCE)
          .expect(400, {
            error: "invalid_request",
            error_description:
              "DPoP-bound access tokens must be used with a DPoP authorization header",
          });
      });
    });

    describe("Scope-protected", () => {
      test("allow access with valid token", async () => {
        const accessToken = await generateAccessToken({
          scope: "read:profile write:profile",
        });

        await request(app)
          .get("/private/scope")
          .set("Authorization", `Bearer ${accessToken}`)
          .expect(200, { message: "Hello from scope-protected endpoint!" });
      });

      test("deny access with valid token and missing scope", async () => {
        const accessToken = await generateAccessToken({
          scope: "read:profile",
        });

        await request(app)
          .get("/private/scope")
          .set("Authorization", `Bearer ${accessToken}`)
          .expect(403, {
            error: "insufficient_scope",
            error_description:
              "Required scopes are: 'read:profile write:profile'",
          });
      });
    });
  });

  describe("token validation", () => {
    const app = setupApi({ protectRoutes: true });

    test("deny access using an invalid 'aud'", async () => {
      const accessToken = await generateAccessToken({
        aud: "invalid-aud",
      });

      await request(app)
        .get("/private/hello")
        .set("Authorization", `Bearer ${accessToken}`)
        .expect(401, {
          error: "invalid_token",
          error_description: "The access token is invalid",
        });
    });

    test("deny access using a expired token", async () => {
      const now = Math.floor(Date.now() / 1000);

      const accessToken = await generateAccessToken({
        iat: now - 10,
        exp: now - 10,
      });

      await request(app)
        .get("/private/hello")
        .set("Authorization", `Bearer ${accessToken}`)
        .expect(401, {
          error: "invalid_token",
          error_description: "The access token is expired",
        });
    });

    test("deny access using an invalid token", async () => {
      await request(app)
        .get("/private/hello")
        .set("Authorization", "Bearer invalid-access-token")
        .expect(401, {
          error: "invalid_token",
          error_description: "The access token is invalid",
        });
    });

    test("deny access using wrong headers", async () => {
      await request(app)
        .get("/private/hello")
        .set("Authorization", "WrongHeader invalid-access-token")
        .expect(401);
    });
  });
});
