import express from "express";
import cors from "cors";
import { authMiddleware, protectRoute } from "express-oauth2-dpop";
import type { Request, Response } from "express";

import { RedisJtiStore } from "./store/redis-jti-store.js";
import { getEnv } from "./utils.js";

const app = express();

app.use(
  cors({
    exposedHeaders: ["DPoP-Nonce", "WWW-Authenticate"],
  }),
);

app.get("/public/hello", function (_req: Request, res: Response) {
  res.json({
    message: "Hello from a public endpoint!",
  });
});

app.use(
  authMiddleware({
    issuer: getEnv("AUTH_ISSUER"),
    jwksUri: getEnv("AUTH_JWKS_UR"),
    audience: getEnv("AUTH_AUDIENCE"),
    protectRoute: false, // When disabled, you need to use protectRoute() middleware to protect the routes
    jtiStore: new RedisJtiStore(),
    nonceSecret: getEnv("AUTH_NONCE_SECRET"),
  }),
);

app.get(
  "/private/bearer",
  protectRoute(),
  function (_req: Request, res: Response) {
    res.json({
      message: "Hello from a Bearer-protected endpoint!",
    });
  },
);

app.get(
  "/private/dpop",
  protectRoute({
    enforceDPoP: true,
  }),
  function (_req: Request, res: Response) {
    res.json({
      message: "Hello from a DPoP-protected endpoint!",
    });
  },
);

app.get(
  "/private/scope",
  protectRoute({
    requiredScopes: ["read:profile", "write:profile"],
  }),
  function (_req: Request, res: Response) {
    res.json({
      message: "Hello from a scope-protected endpoint!",
    });
  },
);

app.use((_req: Request, res: Response) => {
  res.status(404).json({
    error: "not_found",
    error_description: "The requested resource was not found",
  });
});

export default app;
