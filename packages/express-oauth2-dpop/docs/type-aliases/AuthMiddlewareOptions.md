# Type Alias: AuthMiddlewareOptions

> **AuthMiddlewareOptions** = `object`

## Properties

### audience

> **audience**: `string`

The audience for which the access token is intended.

#### Example

```ts
"https://api.example.com"
```

***

### issuer

> **issuer**: `string`

The issuer of the access token.

#### Example

```ts
"https://auth.example.com"
```

***

### jtiStore

> **jtiStore**: [`AbstractJtiStore`](../classes/AbstractJtiStore.md)

Store implementation used to track used JWT IDs (`jti`) and prevent replay attacks.

***

### nonceSecret

> **nonceSecret**: `string`

A secret string used to encrypt and decrypt stateless nonces (JWE).
The string is hashed with SHA-256 to derive a consistent 32-byte encryption key.

This secret should be cryptographically secure and remain consistent
across server restarts to allow decrypting issued nonces.

#### Example

```ts
"a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
```

#### Remarks

Generate a secure secret with:
`openssl rand -hex 32`

***

### enforceDPoP?

> `optional` **enforceDPoP**: `boolean`

If true, the middleware will require a DPoP-bound access token in all protected routes.
If false, it will accept both Bearer and DPoP tokens.

#### Default

```ts
false
```

***

### jwksUri?

> `optional` **jwksUri**: `string`

The URL to the JWKS endpoint.
If not provided, it will default to `{{issuer}}/.well-known/jwks.json`.

#### Default

```ts
{{issuer}}/.well-known/jwks.json
```

#### Example

```ts
"https://auth.example.com/.well-known/jwks.json"
```

***

### protectRoutes?

> `optional` **protectRoutes**: `boolean`

If true, the middleware will automatically protect all routes.
If false, routes must be protected manually using `protectRoute()` middleware.

#### Default

```ts
true
```
