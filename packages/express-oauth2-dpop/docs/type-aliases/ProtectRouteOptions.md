# Type Alias: ProtectRouteOptions

> **ProtectRouteOptions** = `object`

## Properties

### enforceDPoP?

> `optional` **enforceDPoP**: `boolean`

If true, the middleware will require a DPoP-bound access token in all routes.
If false, it will accept both Bearer and DPoP tokens.

#### Default

```ts
false
```

***

### scope?

> `optional` **scope**: `string`[]

List of required scopes for the protected route.
If provided, the access token must include **at least** all listed scopes.
Additional scopes in the token are allowed.
If not provided, no scope validation will be performed.

#### Example

```ts
["read:profile", "write:profile"]
```
