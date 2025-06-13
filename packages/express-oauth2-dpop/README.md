# express-oauth2-dpop

Middleware for Express to protect your API routes (resource server) with OAuth 2.0 JWT Bearer and DPoP-bound access tokens issued by an authorization server.

![Release](https://img.shields.io/npm/v/express-oauth2-dpop)
![Downloads](https://img.shields.io/npm/dw/express-oauth2-dpop)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

## Key Features

- ✅ **Supports both `Bearer` and `DPoP` access tokens:** Seamlessly validates standard Bearer tokens and DPoP-bound JWT access tokens for enhanced security.
- 🔐 **Built-in route protection:** Automatically protect all routes or use fine-grained control with `protectRoute()` middleware.
- 🎯 **Scope-based authorization:** Enforce required OAuth scopes on a per-route basis.
- 🧠 **Pluggable JTI store:** Prevent DPoP replay attacks by plugging in your own JTI store (eg. Redis).
- ⚙️ **Flexible configuration:** Customize issuer, audience, JWKS URI, DPoP enforcement, and more.
- 🌐 **Standards-compliant:** Follows [RFC 9449 (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449) and [RFC 6750 (OAuth 2.0 Authorization Framework)](https://datatracker.ietf.org/doc/html/rfc6750).
- 🧪 **Minimal setup for testing:** Includes a simple in-memory JTI store for local development and testing environments.

## Installation

```bash
npm install express-oauth2-dpop
```

## Getting started

### Set up the auth middleware

To enable token validation in your Express app, apply the `authMiddleware` globally. This middleware will extract and validate access tokens (`Bearer` or `DPoP`) on incoming requests.

```javascript
import express from "express";
import { authMiddleware, protectRoute } from "express-oauth2-dpop";
import { InMemoryJtiStore } from "./store/in-memory-jti-store.js";

const app = express();

app.use(
  authMiddleware({
    issuer: "https://auth.example.com",
    audience: "https://api.example.com",
    jwksUri: "https://auth.example.com/.well-known/openid-configuration/jwks", // Optional: only needed if your JWKS endpoint differs from the default {{issuer}}/.well-known/jwks.json
    protectRoutes: false, // Optional: defaults to true. Use false if you want to manually protect routes with the protectRoute() middleware.
    enforceDPoP: true, // Optional: only needed if you want to enforce DPoP-bound access token
    nonceSecret: process.env.NONCE_SECRET!, // eg. 954860b66dc9d7fc4a8a0f1ceccb285b8d912b144584ffbc253ce336ee40685b
    jtiStore: new InMemoryJtiStore(), // For testing only. Use Redis or a similar store in production.
  })
);
```

### Protect routes

If you prefer more control protecting routes, set `protectRoutes: false` and use the `protectRoute()` middleware:

```javascript
import express from "express";
import { authMiddleware, protectRoute } from "express-oauth2-dpop";

app.use(authMiddleware({
  // ...
  protectRoutes: false,
}));

app.get(
  "/public",
  (req, res) => {
    res.json({
      message: "This is a public endpoint",
    });
  }
);

app.get(
  "/protected",
  protectRoute(),
  (req, res) => {
    res.json({
      message: "This is a protected endpoint",
    });
  }
);
```

#### Enforcing DPoP

You can enforce the use of a DPoP-bound access token on specific routes using the `enforceDPoP` option:

```javascript
import express from "express";
import { authMiddleware, protectRoute } from "express-oauth2-dpop";

app.use(authMiddleware({
  // ...
  protectRoutes: false,
}))

app.get(
  "/protected/dpop",
  protectRoute({
    enforceDPoP: true
  }),
  (req, res) => {
    res.json({
      message: "This is a protected endpont with DPoP-bound access token",
    });
  },
);
```

#### Require scopes

To restrict access based on scopes, use the `scope` option. The request will be rejected if the token doesn't include **at least** all required scopes:

```javascript
app.get(
  "/protected/scope",
  protectRoute({
    scope: ["read:profile", "write:profile"],
  }),
  (req, res) => {
    res.json({
      message: "This is a scope-protected endpoint",
    });
  },
);
```

## JTI Store

To prevent DPoP token replay attacks, the middleware requires a **JTI Store**, a mechanism to store and validate unique JWT IDs (`jti` claims).

For testing purposes, you can use in-memory store. For production usage, you should implement your own store backed by a persistent storage like Redis.

### Implementing the custom store

To create a custom store, extend the `AbstractJtiStore` class and implement two methods:

- `get(identifier: string): Promise<JtiData | undefined>` — Retrieves a JTI entry (if it exists).
- `set(identifier: string, data: JtiData): Promise<void>` — Stores a JTI entry with its expiration.

#### Redis example

```javascript
import { AbstractJtiStore } from "express-oauth2-dpop";
import { createClient } from "redis";
import type { JtiData } from "express-oauth2-dpop";

const client = createClient({
  // ...
});

await client.connect();

export class RedisJtiStore extends AbstractJtiStore {
  async set(identifier: string, data: JtiData): Promise<void> {
    client.set(identifier, JSON.stringify(data), {
      expiration: {
        type: "EXAT",
        value: data.expiresAt,
      },
    });
  }

  async get(identifier: string): Promise<JtiData | undefined> {
    const data = await client.get(identifier);

    if (!data) {
      return undefined;
    }

    return JSON.parse(data) as JtiData;
  }
}
```

#### In-Memory example

```javascript
export class InMemoryJtiStore extends AbstractJtiStore {
  private store: Map<string, JtiData> = new Map();

  /**
   * In-memory implementation of JTI store, intended for development/testing use only.
   *
   * A cleanup routine runs every 60 seconds to remove expired JTI entries
   * and prevent unbounded memory growth.
   */
  constructor() {
    super();
    setInterval(() => {
      void this.deleteExpired();
    }, 60 * 1000);
  }

  async set(identifier: string, data: JtiData): Promise<void> {
    this.store.set(identifier, data);
  }

  async get(identifier: string): Promise<JtiData | undefined> {
    return this.store.get(identifier);
  }

  async delete(identifier: string): Promise<void> {
    this.store.delete(identifier);
  }

  async deleteExpired(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);

    for (const [identifier, data] of this.store.entries()) {
      if (data.expiresAt <= now) {
        this.store.delete(identifier);
      }
    }
  }
}
```

### Using the custom store

Pass your store instance to the middleware configuration:

```javascript
import express from "express";
import { authMiddleware, protectRoute } from "express-oauth2-dpop";
import { RedisJtiStore } from "./store/redis-jti-store.js";

const app = express();

app.use(
  authMiddleware({
    // ...
    jtiStore: new RedisJtiStore(),
  })
);
```


