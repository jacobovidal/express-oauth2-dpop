import nock from "nock";
import { generateKeyPair, calculateJwkThumbprint, exportJWK } from "jose";

export const AUTH_BASE_URL = "http://auth.localhost";

export const { publicKey, privateKey } = await generateKeyPair("RS256");
export const publicJwk = await exportJWK(publicKey);
publicJwk.kid = await calculateJwkThumbprint(publicJwk);
publicJwk.use = "sig";
publicJwk.alg = "RS256";

export function setupJwks(): void {
  nock(AUTH_BASE_URL)
    .persist()
    .get("/.well-known/jwks.json")
    .reply(200, { keys: [publicJwk] });
}
