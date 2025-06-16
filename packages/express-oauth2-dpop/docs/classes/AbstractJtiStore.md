# Class: `abstract` AbstractJtiStore

## Constructors

### Constructor

> **new AbstractJtiStore**(): `AbstractJtiStore`

#### Returns

`AbstractJtiStore`

## Methods

### get()

> `abstract` **get**(`identifier`): `Promise`\<`undefined` \| [`JtiData`](../type-aliases/JtiData.md)\>

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `identifier` | `string` |

#### Returns

`Promise`\<`undefined` \| [`JtiData`](../type-aliases/JtiData.md)\>

***

### set()

> `abstract` **set**(`identifier`, `data`): `Promise`\<`void`\>

#### Parameters

| Parameter | Type |
| ------ | ------ |
| `identifier` | `string` |
| `data` | [`JtiData`](../type-aliases/JtiData.md) |

#### Returns

`Promise`\<`void`\>
