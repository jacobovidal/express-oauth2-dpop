import express from "express";
import type { Express } from "express";
import crypto from "crypto";

import { AUTH_BASE_URL } from "./setup-jwks.js";
import { MockJtiStore } from "../mocks/jti-store-mock.js";
import { authMiddleware } from "../../middlewares/auth-middleware.js";
import { protectRoute } from "../../middlewares/protect-route-middleware.js";

export type ApiOptions = {
  protectRoutes?: boolean;
  enforceDPoP?: boolean;
  audience?: string;
};

export const DEFAULT_AUDIENCE = "api.localhost";

export function setupApi(options: ApiOptions = {}): Express {
  const {
    protectRoutes = false,
    audience = DEFAULT_AUDIENCE,
    enforceDPoP = false,
  } = options;
  const app = express();
  app.get("/public/hello", (req, res) => {
    res.json({
      message: "Hello from public endpoint!",
    });
  });

  app.use(
    authMiddleware({
      issuer: AUTH_BASE_URL,
      audience,
      protectRoutes,
      jtiStore: new MockJtiStore(),
      enforceDPoP,
      nonceSecret: crypto.randomBytes(32).toString("hex"),
    }),
  );

  app.get("/private/bearer", protectRoute(), (_req, res) => {
    res.json({
      message: "Hello from Bearer-protected endpoint!",
    });
  });

  app.get("/private/dpop", protectRoute({ enforceDPoP: true }), (_req, res) => {
    res.json({
      message: "Hello from DPoP-protected endpoint!",
    });
  });

  app.get(
    "/private/scope",
    protectRoute({ scope: ["read:profile", "write:profile"] }),
    (_req, res) => {
      res.json({
        message: "Hello from scope-protected endpoint!",
      });
    },
  );

  app.get("/private/hello", (req, res) => {
    res.json({
      message: "Hello from private endpoint!",
    });
  });

  return app;
}
