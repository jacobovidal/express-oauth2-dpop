import express from "express";
import { authMiddleware, protectRoute } from "express-oauth2-dpop";

import { RedisJtiStore } from "../store/redis-jti-store.js";
import { getEnv } from "../utils.js";

const router = express.Router();

router.use(
  authMiddleware({
    issuer: getEnv("AUTH_ISSUER"),
    jwksUri: getEnv("AUTH_JWKS_URI"),
    audience: getEnv("AUTH_AUDIENCE"),
    protectRoutes: false, // When disabled, you need to use protectRoute() middleware to protect the routes
    jtiStore: new RedisJtiStore(),
    nonceSecret: getEnv("AUTH_NONCE_SECRET"),
  }),
);

router.get("/bearer", protectRoute(), (_req, res) => {
  res.json({
    message: "Hello from a Bearer-protected endpoint!",
  });
});

router.get("/dpop", protectRoute({ enforceDPoP: true }), (_req, res) => {
  res.json({
    message: "Hello from a DPoP-protected endpoint!",
  });
});

router.get(
  "/scope",
  protectRoute({ requiredScopes: ["read:profile", "write:profile"] }),
  (_req, res) => {
    res.json({
      message: "Hello from a scope-protected endpoint!",
    });
  },
);

export default router;
