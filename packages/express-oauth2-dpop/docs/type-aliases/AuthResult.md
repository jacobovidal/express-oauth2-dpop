# Type Alias: AuthResult

> **AuthResult** = `object`

The result of a successfully verified access token.

## Properties

### header

> **header**: `JWSHeaderParameters`

The decoded JWS header of the access token.

***

### payload

> **payload**: `JWTPayload` & `Partial`\<[`BoundAccessToken`](BoundAccessToken.md)\>

The decoded payload of the access token.

***

### token

> **token**: `string`

The original raw JWT string.
