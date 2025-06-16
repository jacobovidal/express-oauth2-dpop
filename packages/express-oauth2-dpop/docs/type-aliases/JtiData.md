# Type Alias: JtiData

> **JtiData** = `object`

Metadata for a stored `jti`, used to prevent DPoP proof replay attacks.

## Properties

### expiresAt

> **expiresAt**: `number`

The time (in seconds since epoch) when this `jti` expires and can be removed from the store.

#### Example

```ts
1750113600
```
