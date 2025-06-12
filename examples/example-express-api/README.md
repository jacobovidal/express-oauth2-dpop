# Express API Example

This example demonstrates how to use the `express-oauth2-dpop` package to protect your API with Bearer or DPoP-bound access tokens issued by an authorization server.

## 🚀 Live Demo

👉 Check our live demo: [`oauth-fetch` Playground](https://oauth-fetch.oauthlabs.com/)

## 📦 Install Dependencies

Install the dependencies using npm:

```bash
npm install
```

## ⚙️ Configuration

This example usis a Redis instance to store JTI values. For testing purposes, you can use the In-Memory abstraction for simplicity:

```javascript
import { InMemoryJtiStore } from "./store/in-memory-jti-store.js";

app.use(
  authMiddleware({
    ...
    jtiStore: new InMemoryJtiStore(),
  }),
);
```

```bash
npm run dev
``` 