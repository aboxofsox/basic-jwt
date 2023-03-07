## Basic JWT
A simple JWT library for creating JWTs in TypeScript.

### Usage
```ts
import {JWT} from 'basic-jwt/lib/jwt'

const payload = {
    username: 'foobar',
    email: 'foo.bar@baz.com',
}
const secret = 'foobarbaz'
const expire = 3600

// Create the JWT with the given data.
const token = JWT.create(payload, secret, expire)

// Verify the JWT
const data = JWT.verify(token, secret)
```

