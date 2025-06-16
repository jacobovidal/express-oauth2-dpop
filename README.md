A monorepo containing the `express-oauth2-dpop` library and example applications.

![Release](https://img.shields.io/npm/v/express-oauth2-dpop)
![Downloads](https://img.shields.io/npm/dw/express-oauth2-dpop)
[![License](https://img.shields.io/:license-mit-blue.svg?style=flat)](https://opensource.org/licenses/MIT)

## 📦 Packages
- [`express-oauth2-dpop`](./packages/express-oauth2-dpop/README.md) - Protect your Express API (resource server) routes with OAuth 2.0 JWT Bearer and DPoP-bound access tokens issued by an authorization server.

## 🚀 Examples

The following example are available:

- [Express API Example](./examples/example-express-api/) — You can also check the live demo here that uses [`oauth-fetch`](https://www.npmjs.com/package/oauth-fetch) and [`express-oauth2-dpop`](https://oauth-fetch.oauthlabs.com/)

Before running the examples, you need to install the dependencies for the monorepo and build all the packages.

1. Install depedencies
```bash
$ npm install
```

2. Build all packages
```bash
$ npm run build
```