# jwt-async [![Build Status](https://secure.travis-ci.org/patbaker82/node-jwt-async.png)](http://travis-ci.org/patbaker82/node-jwt-async)

An async implementation of [JSON Web Tokens (JWT)](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html).

This implementation was developed against `draft-ietf-oauth-json-web-token-32`.  Note that this library leverages core node modules to implement the JWT spec.  The only dependency is lodash, which is used to implement some conveniences.

## Why?

In my search I found that not all node JWT implementations were built with async first in mind.  Additionally I wanted something that allowed for more flexability, but was still able to do the heavy lifting.

It's interesting to note that Node's Crypto.create methods are all **synchronous**.  However the writeable streams to these methods are **asynchronous**.  That means, with this library, the data you want to sign will be **asynchronously** streamed to the relevant crypto methods.  The crypto methods themselves do not perform any heavy crypto computation, therefore its quite fast.

## Installation

```bash
$ npm install jwt-async
```

## Testing

```bash
$ npm test
```

## Example Usage

### Simple example

```javascript
var JWT = require('jwt-async');

// Create jwt instance
// Defaults to HS256 algorithm
var jwt = new JWT();
jwt.setSecret('secret');

// Sign the jwt
jwt.sign({someClaim: 'data'}, function (err, data) {
  if (err) console.log(err);

  // Print signed JWT
  // Paste it into http://www.jwt.io
  console.log(data);

  // Verify it
  jwt.verify(data, function (err, data) {
    if (err) console.log(err);

    // Print the verified JWT
    // This is an object
    console.log(data);
  });
});
```

### Example with options hash

For sake of claity, the options hash is used to set the jwt instance up with some boilerplate.  Meaning, when signing or verifying it will use the options defined.  These can be changed via instance methods documented below. ie `jwt.setSecret`, `jwt.setPrivateKey`, `jwt.setValidations`, `jwt.setClaims`, etc.

```javascript
var JWT = require('jwt-async');

var options = {
  // Default crypto per sign
  crypto: {
    algorithm: 'HS512',
    secret: 'secret'
  },
  // Default claims per sign
  claims: {
    // Automatically set 'Issued At' if true (epoch), or set to a number
    iat: true,
    // Set 'Not Before' claim
    nbf: Math.floor(Date.now() / 1000) - 60,
    // Set 'Expiration' claim
    exp: Math.floor(Date.now() / 1000) + 60,
    // Set a custom claim
    custom: 'this is a custom claim'
  },
  // Default validations per verify
  validations: {
    custom: function (claims, next) {
      // Do custom validation of claims
      // IE verify audience with database, etc
      if (claims.custom === 'this is a custom claim') {
        next();
      } else {
        next(new Error('BOOM'));
      }
    },
    exp: true,
    nbf: true
  }
};

// Create jwt instance
var jwt = new JWT(options);

// More claims that will be merged with the default options
// These will not persist since we're sending them directly to the sign method
var moreClaims = {
  anotherField: 'this is another field'
}

// Sign the jwt
jwt.sign(moreClaims, function (err, data) {
  if (err) console.log(err);

  // Print signed JWT
  // Paste it into http://www.jwt.io
  console.log(data);

  // Verify it
  jwt.verify(data, function (err, data) {
    if (err) console.log(err);

    // Print the verified JWT
    // This is an object
    console.log(data);
  });
});
```

### Example using bluebird promises

If you don't like callbacks, then feel free to use promises.  Here's how you can use this library with a promise library such as bluebird.

```javascript
var JWT = require('jwt-async');
var BPromise = require('bluebird');

var jwt = BPromise.promisifyAll(new JWT());
jwt.setSecret('secret');

jwt.signAsync()
  .then(function (signed) {
    return jwt.verifyAsync(signed);
  })
  .then(function (claims) {
    console.log(claims);
  })
  .catch(JWT.JWTError, function (e) {
    console.log(e);
  });
```

## API

### constructor

#### new JWT([options])

The JWT constructor can take an optional options hash defining some boiler plate for the instance returned.  Once the instance is created, these options can be easily changed by executed the appropriate instance method.  Without an options hash the JWT instance returned will default to HS256 (HMAC) JWT signing.

`options`

The only default set, without options, is the algorithm.  Expect everything else either to be not set or set to false.  Also, if its not obvious, claims are for the signing process and validations are for the verify process.

* crypto
  * algorithm (string) - See below for acceptable algorithms
  * secret (string|buffer) - If using `HS*`, this is the secret used for the symmetric signing
  * privateKey (string|buffer) - If using `RS*`, `ES*` this is the private key used for signing JWT's
  * publicKey (string|buffer) - If using `RS*`, `ES*` this is the public key used for verifying JWT's
* claims
  * iat (boolean|number) If true will set epoch, or can be passed a number if you want something more custom
  * exp (number) The time, typically epoch, for when the JWT should not be valid AFTER
  * nbf (number) The time, typically epoch, for when the JWT should not be valid BEFORE
* validations
  * exp (boolean) If true, the JWT's exp will be validated against the current time in epoch.  If the JWT is > than the current time a JWTExpiredError will be raised.
  * nbf (boolean) If true, the JWT's nbf will be validated against the current time in epoch.  If the JWT is < than the current time a JWTInvalidBeforeTimeError will be raised.
  * custom (function (claims, callback)) If a function is set (see example), any custom validation of the claims can be done.  The function must take two args, claims and a callback.  If the callback is called with an argument it will be converted to a JWTValidationError.  Or you can pass a custom Error().

##### Example

Without options
```javascript
var JWT = require('jwt-async');
var jwt = new JWT;
```

With options; see above for full example
```javascript
var JWT = require('jwt-async');
var jwt = new JWT(options);
```

### instance methods

#### jwt.sign(claims, callback)

`claims`

* (object) Claims to be used for the **current** signing process; they will not be retained and used for the next sign() invocation.  Note, if claims are passed in they will be merged with the claims defined when the jwt instance was setup with options OR any claims that were set with `jwt.setClaims`.

`callback`

* (function (err, data)) - Standard callback with an error object and data.  The data is the signed JWT.

##### Example

```javascript
// Without a claims object
jwt.sign(null, function (err, data) {
  // Log out signed JWT
  console.log(data);
});

// With a claims object to be used for this signing
jwt.sign({customClaim: 'this is a custom claim'}, function (err, data) {
  // Log out signed JWT
  console.log(data);
});

// Enable iat
jwt.sign({iat: true}, function (err, data) {
  // Log out signed JWT
  console.log(data);
});

// Disable iat and add nbf
jwt.sign({iat: false, nbf: 1419405977}, function (err, data) {
  // Log out signed JWT
  console.log(data);
});
```

#### jwt.verify(encodedJWT, callback)

`encodedJWT`

* (string|buffer) - Encoded JWT to be verified.  Make sure the jwt instance object has the appropriate algorithm set and/or secret/public key.

`callback`

* (function (err, data)) - Standard callback with an error object and data.  The data is an object of the decoded & verified JWT.

##### Example

```javascript
jwt.verify(data, function (err, data) {
  // log Error object
  if (err) console.log(err);

  // log decoded and verified JWT object
  console.log(data);
});
```

#### jwt.setValidations(validations)

Note that validations are only processed AFTER a jwt is successfully verified.  IE it was verified against the secret or public key.

`validations`

* (object) - Object of validations to be set on the instance.

  * custom (function (claims, callback)) - Set a custom validation function
  * nbf (boolean) - Set true to validate nbf in JWT
  * exp (boolean) - Set true to validate exp in JWT

##### Example

```javascript
var validations = {
  custom: function (claims, callback) {
    // Custom logic here, return an error to fail the validation
    if (claims.customClaim === 10) callback(new Error('This is bad!');

    // Return successful
    callback();
  },
  nbf: true,
  exp: true
};

jwt.setValidations(validations);
```

#### jwt.setPrivateKey(key)

`key`

* (string|buffer) - Set the private key on the jwt instance

##### Example

```javascript
var privateKey = fs.readFileSync('ec256-private.pem');
jwt.setPrivateKey(privateKey);
```

#### jwt.setPublicKey()

`key`

* (string|buffer) - Set the public key on the jwt instance

##### Example

```javascript
var publicKey = fs.readFileSync('ec256-public.pem');
jwt.setPrivateKey(publicKey);
```

#### jwt.setAlgorithm(algorithm)

`algorithm`

* (string) - Set algorithm on the jwt instance; see below for a table of supported algorithms.

##### Example

```javascript
jwt.setAlgorithm('ES512');
```

#### jwt.setClaims(claims)

`claims`

* (object) - Claims to be set on the jwt instance.  These claims will be used for each signing invocation.  If any claims are passed to sign(), they will be merged with the claims set on the instance.

##### Example

```javascript
var claims = {
  // If iat is set to true, an epoch date will be generated automatically.
  iat: true,
  customClaim: 'this is a custom claim'
};

jwt.setClaims(claims);
```
#### jwt.isHmac()

* Returns true if algorithm selected is hmac based.

#### jwt.isSign()

* Returns true if algorithm selected uses keys to sign JWT

#### jwt.isUnsecured()

* Returns true if algorithm is set to 'NONE'

#### jwt.getAlgorithm()

* Returns the algorithm set on the instance

#### jwt.getCrypto()

* Returns the underlying node crypto algorithm that will be used

#### jwt.getHeader()

* Returns the set of headers set on the instance

#### jwt.getClaims()

* Returns the set of claims set of the instance

#### jwt.getSecret()

* Returns the secret set on the instance

#### jwt.getPrivateKey()

* Returns the privateKey set on the instance

#### jwt.getPublicKey()

* Returns the public key set on the instance

#### jwt.getValidations()

* Returns the validations set on the instance

### class methods

#### JWT.getSupportedAlgorithms()

* Returns (object) of the supported algorithms that this library supports

#### JWT.base64urlDecode(str)
#### JWT.base64urlUnescape(str)
#### JWT.base64urlEncode(str)
#### JWT.base64urlEscape(str)

### Errors

For methods that are callback based an error will be set on callback if neccessary.

#### JWTError

JWTError is typically raised for generic type of error events.  IE you tried to sign a JWT with algorithm ES256, but you don't have a privateKey set.

#### JWTValidationError

JWTValidationError is raised when a JWT fails the basic validation process.  IE either the library wasn't able to verify that the JWT signed correctly, it was tampered with, unparseable, etc.

#### JWTExpiredError

JWTExpiredError is raised when the current time is after the JWT claims exp time.  This error also exposes an `expiredAt` property on the error object that reflects when the JWT expired.  Note that you must have exp validations enabled.

#### JWTInvalidBeforeTimeError

JWTInvalidBeforeTimeError is raised when the current time is before the JWT claims nbf time.  This error also exposes an `invalidBefore` property on the error object that reflects when the JWT will be valid after.  Note that you must have nbf validations enabled.

## Algorithms supported

Algorithm | Description| Supported?
----------------|----------------|----------------
none | No digital signature or MAC performed | ✓
HS256 | HMAC using SHA-256 | ✓
HS384 | HMAC using SHA-384 | ✓
HS512 | HMAC using SHA-512 | ✓
RS256 | RSASSA-PKCS-v1_5 using SHA-256| ✓
RS384 | RSASSA-PKCS-v1_5 using SHA-384 | ✓
RS512 | RSASSA-PKCS-v1_5 using SHA-512 | ✓
ES256 | ECDSA using P-256 and SHA-256 | ✓
ES384 | ECDSA using P-384 and SHA-384 | ✓
ES512 | ECDSA using P-521 and SHA-512 | ✓
PS256 | RSASSA-PSS using SHA-256 and MGF1 with SHA-256 | ✖
PS384 | RSASSA-PSS using SHA-384 and MGF1 with SHA-384 | ✖
PS512 | RSASSA-PSS using SHA-512 and MGF1 with SHA-512 | ✖

# Caveats

X.509 certificate support is not implemented

# License

MIT
