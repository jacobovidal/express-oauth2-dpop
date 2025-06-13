import crypto from "crypto";
import { EncryptJWT, jwtDecrypt } from "jose";

import type { NonceData } from "../types/types.internal.js";
import type { AuthMiddlewareOptions } from "../types/types.js";

const NONCE_EXPIRATION = 60 * 5;

async function deriveAesGcmKeyFromNonceSecret(
  nonceSecret: string,
): Promise<CryptoKey> {
  const keyMaterial = crypto
    .createHash("sha256")
    .update(nonceSecret, "utf8")
    .digest();

  return await crypto.subtle.importKey(
    "raw",
    keyMaterial,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function createStatelessNonce(
  ath: string,
  authOptions: AuthMiddlewareOptions,
): Promise<string> {
  const exp = Math.floor(Date.now() / 1000) + NONCE_EXPIRATION;

  const secretKey = await deriveAesGcmKeyFromNonceSecret(
    authOptions.nonceSecret,
  );

  return await new EncryptJWT({ ath })
    .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
    .setIssuedAt()
    .setExpirationTime(exp)
    .encrypt(secretKey);
}

export async function decryptStatelessNonce(
  nonce: string,
  authOptions: AuthMiddlewareOptions,
): Promise<NonceData> {
  const secretKey = await deriveAesGcmKeyFromNonceSecret(
    authOptions.nonceSecret,
  );

  const { payload } = await jwtDecrypt(nonce, secretKey);

  return payload as NonceData;
}
