/*
 * jwt-async
 *
 * JSON Web Token (JWT) with asynchronicity
 *
 * Copyright(c) 2014 Patrick Baker <patricksbaker@gmail.com>
 * MIT Licensed
 */
'use strict';

/**
 * node dependencies
 */
var Crypto = require('crypto');
var Util = require('util');

/**
 * external dependencies
 */
var _ = require('./lodash');

/**
 * Error messages
 */
var ERROR_CALLBACK_UNDEFINED = 'callback is undefined';
var ERROR_BAD_SIGNATURE = 'JWT signature does not match - possible tampering detected';
var ERROR_EXPIRED = 'JWT expired at';
var ERROR_NOT_VALID_UNTIL = 'JWT not valid until';
var ERROR_CLAIMS_UNDEFINED = 'claims is undefined';
var ERROR_UNKNOWN_SIGN_METHOD = 'unable to determine JWT signing type - asymmetrical or symmetrical';
var ERROR_PRIVATE_KEY_REQUIRED = 'private key is required for asymmetrical signing';
var ERROR_PUBLIC_KEY_REQUIRED = 'public key is required for asymmetrical signature verification';
var ERROR_SECRET_REQUIRED = 'secret required for symmetrical signing';
var ERROR_JWT_UNDEFINED = 'JWT is undefined';
var ERROR_JWT_FORMAT = 'JWT is not in the expected format';
var ERROR_UNKNOWN_VALIDATION = 'unable to validate claims - unknown error';
var ERROR_JWT_UNPARSABLE = 'JWT is unparsable';
var JWT_UNKNOWN_ALGORITHM = 'provided algorithm is unknown to the JWT spec';

/**
 * Create an instance of JWT
 * @constructor
 * @returns {Object} JWT instance
 *
 */
function JWT (options) {
  options = options || {};
  var optionDefaults = {
    crypto: {
      algorithm: 'HS256'
    },
    header: {
      typ: 'JWT'
    },
    claims: {},
    validations: {}
  };
  _.defaultsDeep(options, optionDefaults);

  // -- Private
  var isHmac = false;
  var isSign = false;
  var isUnsecured = false;
  var validations;

  var algPrefix;
  var algBitLength;
  var algorithm;
  var crypto;

  var privateKey;
  var publicKey;
  var secret;

  var jwtClaims;
  var jwtHeader;

  function processKey (key) {
    if (!_.isUndefined(key)) {
      if (Buffer.isBuffer(key)) {
        return key.toString();
      } else {
        return key;
      }
    } else {
      return key;
    }
  }

  // -- Protected
  this.isHmac = function () {
    return isHmac;
  };

  this.isSign = function () {
    return isSign;
  };

  this.isUnsecured = function () {
    return isUnsecured;
  };

  this.getAlgorithm = function () {
    return algorithm;
  };

  this.getCrypto = function () {
    return crypto;
  };

  this.getHeader = function () {
    return jwtHeader;
  };

  this.getClaims = function () {
    return jwtClaims;
  };

  this.getSecret = function () {
    return secret;
  };

  this.getPrivateKey = function () {
    return privateKey;
  };

  this.getPublicKey = function () {
    return publicKey;
  };

  this.getValidations = function () {
    return validations;
  };

  // Public
  this.setValidations = function (obj) {
    validations = obj || {};
    return this;
  };

  this.setPrivateKey = function (key) {
    privateKey = processKey.bind(this)(key) || undefined;
    return this;
  };

  this.setPublicKey = function (key) {
    publicKey = processKey.bind(this)(key) || undefined;
    return this;
  };

  this.setSecret = function (sec) {
    if (!_.isUndefined(sec)) {
      if (Buffer.isBuffer(sec)) {
        secret =  sec.toString();
      } else {
        secret = sec;
      }
    } else {
      secret = sec;
    }
    return this;
  };

  this.setAlgorithm = function (alg) {
    if (_.has(JWT.getSupportedAlgorithms(), alg)) {
      jwtHeader = _.merge(options.header, { alg: alg.toUpperCase() });
      if (alg === 'NONE') {
        isHmac = false;
        isSign = false;
        isUnsecured = true;
        crypto = '';
      } else {
        algorithm = alg.toUpperCase();
        algPrefix = alg.substring(0,2);
        algBitLength = alg.substring(2,5);

        // Set type key
        if (algPrefix === 'RS'
            || algPrefix === 'ES'
            || algPrefix === 'PS'
        ) {
          isHmac = false;
          isSign = true;
          isUnsecured = false;
          crypto = 'RSA-SHA' + algBitLength;
        } else {
          isHmac = true;
          isSign = false;
          isUnsecured = false;
          crypto = 'sha' + algBitLength;
        }
      }
    } else {
      throw new JWTError(JWT_UNKNOWN_ALGORITHM + ' ' +  alg);
    }
    return this;
  };

  this.setClaims = function(claims) {
    jwtClaims = claims;
    return this;
  };

  //-- Initialization
  // Set header / alg
  this.setAlgorithm(options.crypto.algorithm);

  // Set secret / keys
  if (!_.isUndefined(options.crypto.secret)) {
    this.setSecret(options.crypto.secret);
  }

  if (!_.isUndefined(options.crypto.privateKey)) {
    this.setPrivateKey(options.crypto.privateKey);
  }

  if (!_.isUndefined(options.crypto.publicKey)) {
    this.setPublicKey(options.crypto.publicKey);
  }

  // Set default claims
  this.setClaims(options.claims);

  // Set Validations
  this.setValidations(options.validations);

  // Return instance
  return this;
}

/**
 * Sign a JWT
 *
 */
JWT.prototype.sign = function (claims, callback) {
  claims = claims || {};
  _.defaultsDeep(claims, this.getClaims());
  var jwt = [];

  if (typeof claims === 'function') {
    callback = claims;
    claims = {};
  }

  if (_.isUndefined(callback)) {
    throw new JWTError(ERROR_CALLBACK_UNDEFINED);
  }

  // Process time based options
  if (!_.isUndefined(claims.iat)) {
    if (claims.iat === true) {
      claims.iat = Math.floor(Date.now() / 1000);
    } else if (!_.isNumber(claims.iat)
              || claims.iat === false) {
      delete claims.iat;
    }
  }

  // Build JWT header & claims
  jwt.push(JWT.base64urlEncode(JSON.stringify(this.getHeader())));
  jwt.push(JWT.base64urlEncode(JSON.stringify(claims)));

  // Process HMAC signature
  if (this.isUnsecured()) {
    return callback(null, jwt.join('.') + '.');
  } else {
    this.encode(jwt.join('.'), function (err, data) {
      if (err) return callback(err);
      jwt.push(data);
      return callback(null, jwt.join('.'));
    });
  }
};

/**
 * Verify a JWT
 *
 */
JWT.prototype.verify = function (jwt, callback) {
  var jwtSplit;
  var jwtHeader;
  var jwtClaims;
  var jwtSignature;
  var jwtObject = {};
  var _this = this;

  //-- Pre flight
  if (typeof jwt === 'function') {
    callback = jwt;
    jwt = undefined;
  }

  if (typeof callback === 'undefined') {
    throw new JWTError(ERROR_CALLBACK_UNDEFINED);
  }

  if (typeof jwt === 'undefined') {
    return callback(new JWTError(ERROR_JWT_UNDEFINED));
  }

  if (Buffer.isBuffer(jwt)) {
    jwtSplit = jwt.toString().split('.');
  } else {
    jwtSplit = jwt.split('.');
  }

  if (jwtSplit.length !== 3) {
    return callback(new JWTValidationError(ERROR_JWT_FORMAT));
  }

  jwtHeader = JWT.base64urlDecode(jwtSplit[0]);
  jwtClaims = JWT.base64urlDecode(jwtSplit[1]);
  jwtSignature = jwtSplit[2];

  try {
    jwtObject.header = JSON.parse(jwtHeader);
  } catch (e) {
    return callback(new JWTValidationError(ERROR_JWT_UNPARSABLE));
  }

  try {
    jwtObject.claims = JSON.parse(jwtClaims);
  } catch (e) {
    return callback(new JWTValidationError(ERROR_JWT_UNPARSABLE));
  }

  //-- Verify authenticity
  if (this.isUnsecured()) {
    this.verifyClaims(jwtClaims, function (err, validated) {
      if (err) return callback(err);
      if (validated === true) {
        return callback(null, jwtObject);
      } else {
        return callback(new JWTValidationError(ERROR_UNKNOWN_VALIDATION));
      }
    });
  } else if (this.isHmac()) {
    this.encode(JWT.base64urlEncode(jwtHeader) + '.' + JWT.base64urlEncode(jwtClaims), function (err, data) {
      if (err) return callback(err);
      if (!(data === jwtSignature)) {
        return callback(new JWTValidationError(ERROR_BAD_SIGNATURE));
      } else {
        // Process JWT Claims
        _this.verifyClaims(jwtClaims, function (err, validated) {
          if (err) return callback(err);
          if (validated === true) {
            return callback(null, jwtObject);
          } else {
            return callback(new JWTValidationError());
          }
        });
      }
    });
    // out of scope! we already entered a callback
  } else if (this.isSign()) {
    // Check for public key
    if (_.isUndefined(this.getPublicKey())) {
      return callback(new JWTError(ERROR_PUBLIC_KEY_REQUIRED));
    }

    // Since this is the only place where we will validate a public key against a signature
    // I guess it doesn't make sense to abstract it out into its own method
    var cryptoVerifyStream = Crypto.createVerify(this.getCrypto());

    // Emitters
    try {
      cryptoVerifyStream
        .on('error', function (err) {
          return callback(err);
        });

      cryptoVerifyStream.write(JWT.base64urlEncode(jwtHeader) + '.' + JWT.base64urlEncode(jwtClaims), function () {
        if (cryptoVerifyStream.verify(_this.getPublicKey(), JWT.base64urlUnescape(jwtSignature), 'base64') === false) {
          return callback(new JWTError(ERROR_BAD_SIGNATURE));
        } else {
          // Process JWT Claims
          _this.verifyClaims(jwtClaims, function (err, validated) {
            if (err) return callback(err);
            if (validated === true) {
              return callback(null, jwtObject);
            } else {
              return callback(new JWTValidationError(ERROR_UNKNOWN_VALIDATION));
            }
          });
          // out of scope! we already entered a callback
        }
      });
      // out of scope! we already entered a callback
    } catch (e) {
      return callback(e);
    }
  }
};

/**
 * Encode a JWT
 *
 */
JWT.prototype.encode = function (str, callback) {
  if (_.isUndefined(callback)) {
    return callback(new JWTError(ERROR_CALLBACK_UNDEFINED));
  }

  if (this.isHmac()) {
    // Check for secret
    if (_.isUndefined(this.getSecret())) {
      return callback(new JWTError(ERROR_SECRET_REQUIRED));
    }

    // Setup HMAC Stream
    try {
      var cryptoHmacStream = Crypto.createHmac(this.getCrypto(), this.getSecret());

      // Emitters
      cryptoHmacStream
        .on('error', function (err) {
          return callback(err);
        });

      // Write the data
      cryptoHmacStream.write(str, 'utf8', function () {
        cryptoHmacStream.end();
        return callback(null, JWT.base64urlEncode(cryptoHmacStream.read()));
      });
      // out of scope! we already entered a callback
    } catch (e) {
      return callback(e);
    }
  } else if (this.isSign()) {
    var _this = this;

    // Check for privateKey
    if (_.isUndefined(_this.getPrivateKey())) {
      return callback(new JWTError(ERROR_PRIVATE_KEY_REQUIRED));
    }

    try {
      // Setup Crypto Stream
      var cryptoSignStream = Crypto.createSign(this.getCrypto());

      // Emitters
      cryptoSignStream
        .on('error', function (err) {
          return callback(err);
        });

      // Write the data
      cryptoSignStream.write(str, 'utf8', function () {
        cryptoSignStream.end();
        return callback(null, JWT.base64urlEncode(cryptoSignStream.sign(_this.getPrivateKey())));
      });
      // out of scope! we already entered a callback
    } catch (e) {
      return callback(e);
    }
  } else {
    return callback(new JWTError(ERROR_UNKNOWN_SIGN_METHOD));
  }
};

/**
 * Verify JWT claims
 *
 */
JWT.prototype.verifyClaims = function (claims, callback) {
  // Standard validation
  if (_.isUndefined(callback)) {
    return callback(new JWTError(ERROR_CALLBACK_UNDEFINED));
  }

  if (_.isUndefined(claims)) {
    return callback(new JWTValidationError(ERROR_CLAIMS_UNDEFINED));
  }

  // Convert to object
  claims = JSON.parse(claims);

  // Get Validations
  var validationSettings = this.getValidations();

  //-- Validations
  if (!_.isUndefined(validationSettings)) {
    // nbf (Not Before)
    if (!_.isUndefined(claims.nbf)
        && !_.isUndefined(validationSettings.nbf)
        && validationSettings.nbf === true
    ) {
      if (Date.now() / 1000 < claims.nbf) {
        return callback(new JWTInvalidBeforeTimeError(ERROR_NOT_VALID_UNTIL + ' ' + claims.nbf, claims.nbf));
      }
    }

    // exp (Expiration Time)
    if (!_.isUndefined(claims.exp)
        && !_.isUndefined(validationSettings.exp)
        && validationSettings.exp === true
    ) {
      if (Date.now() / 1000 > claims.exp) {
        return callback(new JWTExpiredError(ERROR_EXPIRED + ' ' + claims.exp, claims.exp));
      }
    }

    // Custom validations
    if (!_.isUndefined(validationSettings.custom)
        && validationSettings.custom instanceof Function
    ) {
      validationSettings.custom(claims, function(err, success) {
        // Error handling for custom
        // Can take string or type of Error
        if (err) {
          if (typeof err === 'string') {
            return callback(new JWTValidationError(err))
          } else if (err instanceof Error) {
            return callback(err);
          }
        } else {
          // No error and in callback, so return true
          callback(null, true)
        }
      });
    } else {
      // Last predicate disabled so return good
      callback(null, true)
    }
  } else {
    // Validations disabled
    callback(null, true)
  }
};

/**
 * Object of supported algorithms
 *
 */
JWT.getSupportedAlgorithms = function () {
  return {
    NONE: 'No digital signature or MAC performed',
    HS256: 'HMAC using SHA-256',
    HS384: 'HMAC using SHA-384',
    HS512: 'HMAC using SHA-512',
    RS256: 'RSASSA-PKCS-v1_5 using SHA-256',
    RS384: 'RSASSA-PKCS-v1_5 using SHA-384',
    RS512: 'RSASSA-PKCS-v1_5 using SHA-512',
    ES256: 'ECDSA using P-256 and SHA-256',
    ES384: 'ECDSA using P-384 and SHA-384',
    ES512: 'ECDSA using P-521 and SHA-512'
    /**
     * Node doesn't have support for the PSS signature format
      PS256: 'RSASSA-PSS using SHA-256 and MGF1 with SHA-256',
      PS384: 'RSASSA-PSS using SHA-384 and MGF1 with SHA-384',
      PS512: 'RSASSA-PSS using SHA-512 and MGF1 with SHA-512'
     */
  }
};

/**
 * Utility
 *
 */
JWT.base64urlDecode = function (str) {
  return new Buffer(JWT.base64urlUnescape(str), 'base64').toString();
};

JWT.base64urlUnescape = function (str) {
  str += new Array(5 - str.length % 4).join('=');
  return str.replace(/\-/g, '+').replace(/_/g, '/');
};

JWT.base64urlEncode = function (str) {
  return JWT.base64urlEscape(new Buffer(str).toString('base64'));
};

JWT.base64urlEscape = function (str) {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

/**
 * Error class
 *
 */
function JWTError (message) {
  Error.call(this);
  Error.captureStackTrace(this, JWTError);

  this.name = 'JWTError';
  this.message = message;
}
Util.inherits(JWTError, Error);

function JWTValidationError (message) {
  Error.call(this);
  Error.captureStackTrace(this, JWTValidationError);

  this.name = 'JWTValidationError';
  this.message = message;
}
Util.inherits(JWTValidationError, JWTError);

function JWTExpiredError (message, expiredAt) {
  Error.call(this);
  Error.captureStackTrace(this, JWTExpiredError);

  this.name = 'JWTExpiredError';
  this.message = message;
  this.expiredAt = expiredAt;
}
Util.inherits(JWTExpiredError, JWTValidationError);

function JWTInvalidBeforeTimeError (message, invalidBefore) {
  Error.call(this);
  Error.captureStackTrace(this, JWTInvalidBeforeTimeError);

  this.name = 'JWTInvalidBeforeTimeError';
  this.message = message;
  this.invalidBefore = invalidBefore;
}
Util.inherits(JWTInvalidBeforeTimeError, JWTValidationError);

/**
 * Module exportables
 *
 */
module.exports = JWT;
module.exports.JWTError = JWTError;
module.exports.JWTValidationError = JWTValidationError;
module.exports.JWTExpiredError = JWTExpiredError;
module.exports.JWTInvalidBeforeTimeError = JWTInvalidBeforeTimeError;
