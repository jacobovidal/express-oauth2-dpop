import crypto from "crypto";
import {
  base64url,
  calculateJwkThumbprint,
  EncryptJWT,
  jwtDecrypt,
  generateSecret,
} from "jose";
import type { Request, Response } from "express";

import { AbstractJtiStore } from "../store/abstract-jti-store.js";
import { UseDpopNonce } from "../errors/errors.js";
import type { JWK, JWTHeaderParameters } from "jose";
import type { DpopProofPayload, NonceData } from "../types/types.internal.js";

const IAT_LEEWAY = 30;
const NONCE_EXPIRATION = 60 * 5;
const NONCE_SECRET = await generateSecret("A256GCM");

async function createNonce(ath: string): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + NONCE_EXPIRATION;

  return await new EncryptJWT({ ath })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(exp)
    .encrypt(NONCE_SECRET);
}

async function decryptNonce(nonce: string): Promise<NonceData> {
  const { payload } = await jwtDecrypt(nonce, NONCE_SECRET);

  return payload as NonceData;
}

export function validateProofHeaders(headers: JWTHeaderParameters): void {
  if (headers.typ !== "dpop+jwt") {
    throw new Error("DPoP 'typ' header must be 'dpop+jwt'");
  }

  if (headers.alg) {
    // TODO: validate dpop_signing_alg_values_supported
  }
}

export function validateIat(iat: DpopProofPayload["iat"]): void {
  if (!iat) {
    throw new Error("DPoP 'iat' claim is required");
  }

  const now = Math.floor(Date.now() / 1000);

  const lowerBound = now - IAT_LEEWAY;
  const upperBound = now + IAT_LEEWAY;

  if (iat < lowerBound || iat > upperBound) {
    throw new Error(
      `DPoP 'iat' is not within acceptable time range: expected between ${lowerBound} and ${upperBound}, got ${iat}`
    );
  }
}

export function validateHtm(req: Request, htm: DpopProofPayload["htm"]): void {
  if (!htm) {
    throw new Error("DPoP 'htm' claim is required");
  }

  const expectedMethod = req.method.toUpperCase();

  if (htm !== expectedMethod) {
    throw new Error(
      `DPoP 'htm' mismatch: expected '${expectedMethod}', got '${htm}'`
    );
  }
}

export function validateHtu(req: Request, htu: DpopProofPayload["htu"]): void {
  if (!htu) {
    throw new Error("DPoP 'htu' claim is required");
  }

  const expectedUrl = `${req.protocol}://${req.get("host")}${req.path}`;

  if (htu !== expectedUrl) {
    throw new Error(
      `DPoP 'htu' mismatch: expected "${expectedUrl}", got "${htu}"`
    );
  }
}

export async function validateJwk(jwk: JWK, jkt: string): Promise<void> {
  const expectedJkt = await calculateJwkThumbprint(jwk);

  if (jkt !== expectedJkt) {
    throw new Error(
      `DPoP 'jkt' mismatch: expected '${expectedJkt}', got '${jkt}'`
    );
  }
}

export async function validateAth(
  token: string,
  ath: DpopProofPayload["ath"]
): Promise<void> {
  if (!ath) {
    throw new Error("DPoP 'ath' claim is required");
  }

  const digest = crypto.createHash("sha256").update(token).digest();
  const expectedAth = base64url.encode(digest);

  if (ath !== expectedAth) {
    throw new Error(
      `DPoP 'ath' mismatch: expected '${expectedAth}', got '${ath}'`
    );
  }
}

export async function validateJti(
  jti: DpopProofPayload["jti"],
  jtiStore: AbstractJtiStore
): Promise<void> {
  if (!jti) {
    throw new Error("DPoP 'jti' claim is required");
  }

  const doesJtiExist = await jtiStore.get(jti);

  if (doesJtiExist) {
    throw new Error("DPoP 'jti' has already been used");
  }

  const now = Math.floor(Date.now() / 1000);

  await jtiStore.set(jti as string, {
    expiresAt: now + IAT_LEEWAY,
  });
}

export async function validateNonce(
  nonce: DpopProofPayload["nonce"],
  ath: DpopProofPayload["ath"],
  res: Response
): Promise<void> {
  const newNonce = await createNonce(ath as string);

  if (!nonce) {
    res.setHeader("DPoP-Nonce", newNonce);

    throw new UseDpopNonce("DPoP 'nonce' claim is required");
  }

  try {
    const { ath: nonceAth, exp: nonceExp } = await decryptNonce(nonce);

    if (ath !== nonceAth) {
      throw new Error();
    }

    const now = Math.floor(Date.now() / 1000);

    if (nonceExp - now < 60) {
      res.setHeader("DPoP-Nonce", newNonce);
    }
  } catch {
    res.setHeader("DPoP-Nonce", newNonce);

    throw new UseDpopNonce("DPoP 'nonce' is not valid");
  }
}
