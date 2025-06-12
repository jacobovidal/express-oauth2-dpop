import express from "express";
import cors from "cors";
import { authMiddleware, protectRoute } from "express-oauth2-dpop";
import type { Request, Response } from "express";

import { InMemoryJtiStore } from "./store/in-memory-jti-store.js";

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
    issuer: "https://demo.duendesoftware.com",
    jwksUri:
      "https://demo.duendesoftware.com/.well-known/openid-configuration/jwks",
    audience: "api",
    protectRoute: false, // When disabled, you need to use protectRoute() middleware to protect the routes
    jtiStore: new InMemoryJtiStore(),
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

app.listen(3000, () => console.log("Server ready on port 3000."));

export default app;
