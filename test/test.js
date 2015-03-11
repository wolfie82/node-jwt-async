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
 * Test frameworks
 *
 */
var chai = require('chai');
var expect = chai.expect;
var sinon = require("sinon");
var sinonChai = require("sinon-chai");
chai.use(sinonChai);

/**
 * Other dependencies
 *
 */
var JWT = require('../lib/jwt');
var fs = require('fs');
var _ = require('lodash');

var keyMap = {
  ES256: {
    privateKey: fs.readFileSync('./test/ec256-private.pem'),
    publicKey: fs.readFileSync('./test/ec256-public.pem'),
    invalidPublic: fs.readFileSync('./test/ec256-wrong-public.pem')
  },
  ES384: {
    privateKey: fs.readFileSync('./test/ec384-private.pem'),
    publicKey: fs.readFileSync('./test/ec384-public.pem'),
    invalidPublic: fs.readFileSync('./test/ec384-wrong-public.pem')
  },
  ES512: {
    privateKey: fs.readFileSync('./test/ec512-private.pem'),
    publicKey: fs.readFileSync('./test/ec512-public.pem'),
    invalidPublic: fs.readFileSync('./test/ec512-wrong-public.pem')
  },
  RS: {
    privateKey: fs.readFileSync('./test/rsa-private.pem'),
    publicKey: fs.readFileSync('./test/rsa-public.pem'),
    invalidPublic: fs.readFileSync('./test/rsa-wrong-public.pem')
  }
};

describe('JWT', function () {

  var jwt;
  beforeEach(function newJWT () {
    jwt = new JWT;
  });

  describe('when creating a vanilla instance', function () {
    it('should default to HS256', function () {
      expect(jwt.getAlgorithm()).to.be.a('string').and.equal('HS256');
    });

    it('should have a header set', function () {
      expect(jwt.getHeader()).to.be.a('object').and.eql(
        {
          alg: 'HS256',
          typ: 'JWT'
        }
      );
    });

    it('should have no claims', function () {
      expect(jwt.getClaims()).to.be.a('object').and.eql({});
    });

    it('should have no validations enabled', function () {
      expect(jwt.getValidations()).to.be.a('object').and.eql({});
    });
  });

  describe('when passing options to constructor', function () {

    var date;
    var options;

    beforeEach(function () {
      date = Math.floor(Date.now() / 1000);
      options = {
        crypto: {
          algorithm: 'HS512',
          secret: 'test secret',
          privateKey: 'test privateKey',
          publicKey: 'test publicKey'
        },
        header: {
          typ: 'JWT',
          custom: 'header'
        },
        claims: {
          iat: date,
          nbf: date,
          exp: date
        },
        validations: {
          nbf: date,
          exp: date,
          custom: function () {
          }
        }
      };

      jwt = new JWT(options);
    });

    it('should set options', function () {
      expect(jwt.getAlgorithm()).to.be.a('string').and.equal(options.crypto.algorithm);
      expect(jwt.getSecret()).to.be.a('string').and.equal(options.crypto.secret);
      expect(jwt.getPrivateKey()).to.be.a('string').and.equal(options.crypto.privateKey);
      expect(jwt.getPublicKey()).to.be.a('string').and.equal(options.crypto.publicKey);
      expect(jwt.getHeader()).to.be.a('object').and.eql(options.header);
      expect(jwt.getClaims()).to.be.a('object').and.eql(options.claims);
      expect(jwt.getValidations()).to.be.a('object').and.eql(options.validations);
    });

  });

  describe('when changing algorithms', function () {
    it('should change the algorithm', function () {
      jwt.setAlgorithm('HS512');
      expect(jwt.getAlgorithm()).to.be.a('string').and.equal('HS512');
    });

    it('should select correct node crypto hashing mechanism', function () {
      for (var k in JWT.getSupportedAlgorithms()) {
        var algPrefix = k.substring(0,2);
        var algBitLength = k.substring(2,5)
        jwt.setAlgorithm(k);

        if (algPrefix === 'RS'
            || algPrefix === 'ES'
            || algPrefix === 'PS'
        ) {
          expect(jwt.getCrypto()).to.be.a('string').and.equal('RSA-SHA' + algBitLength);
        } else if (algPrefix === 'HS') {
          expect(jwt.getCrypto()).to.be.a('string').and.equal('sha' + algBitLength);
        } else {
          expect(jwt.getCrypto()).to.be.a('string').and.empty();
        }
      }
    });

    it('should not allow an invalid algorithm', function () {
      expect(jwt.setAlgorithm.bind(null, 'XXXX')).to.throw(JWT.JWTError);
    });
  });

  _.forOwn(JWT.getSupportedAlgorithms(), function (k, v) {


    describe('when signing with ' + v, function () {


      it('should sign successfully', function (done) {
        setupAlgorithm(v, jwt);
        jwt.sign(null, function (err, data) {
          expect(err).to.be.null;
          done();
        });
      });

      it('should be in the correct format', function (done) {
        setupAlgorithm(v, jwt);
        jwt.sign(null, function (err, data) {
          expect(data.split('.').length).to.equal(3);
          done();
        });
      });

      if (v === 'NONE') {
        it('should be missing signature if algorithm is none', function (done) {
          setupAlgorithm(v, jwt);
          jwt.sign(null, function (err, data) {
            expect(data.split('.')[2]).to.be.empty();
            done();
          });
        });
      }

      it('should throw an error if a callback is not defined', function (done) {
        setupAlgorithm(v, jwt);
        expect(jwt.sign.bind(jwt)).to.throw(JWT.JWTError);
        done();
      });

      it('should have default claims (setup when object created)', function (done) {
        var mockClaims = {
          iat: 1234,
          custom: 'test'
        };

        setupAlgorithm(v, jwt);
        jwt.setClaims(mockClaims);
        jwt.sign(null, function (err, data) {
          expect(JSON.parse(JWT.base64urlDecode(data.split('.')[1]))).to.be.a('object').and.eql(mockClaims);
          done();
        });
      });

      it('should merge claims with default when passed to .sign()', function (done) {
        var mockClaims = {
          iat: 1234,
          custom: 'test'
        };

        var newMockClaims = {
          iat: false
        };

        var expectedResult = {
          custom: 'test'
        };

        setupAlgorithm(v, jwt);
        jwt.setClaims(mockClaims);
        jwt.sign(newMockClaims, function (err, data) {
          expect(JSON.parse(JWT.base64urlDecode(data.split('.')[1]))).to.be.a('object').and.eql(expectedResult);
          done();
        });
      });
    });

    describe('when verifying with ' + v, function () {
      it('should verify with correct signature', function (done) {
        setupAlgorithm(v, jwt);
        var mockObj = {
          header: {
            typ: 'JWT',
            alg: v
          },
          claims: {}
        };

        jwt.sign(null, function (signErr, signData) {
          expect(signErr instanceof Error).to.be.false;
          jwt.verify(signData, function (verifyErr, verifyData) {
            expect(verifyErr instanceof Error).to.be.false;
            expect(verifyData).to.be.an('object').and.eql(mockObj);
            done();
          });
        });
      });

      it('should not verify with incorrect signature', function (done) {
        var algPrefix = v.substr(0, 2);
        var algBitLength = v.substring(2,5)
        setupAlgorithm(v, jwt);

        jwt.sign(null, function (signErr, signData) {
          expect(signErr instanceof Error).to.be.false;

          if (algPrefix === 'ES') {
            jwt.setPublicKey(keyMap['ES'+algBitLength].invalidPublic);
          } else if (algPrefix === 'RS') {
            jwt.setPublicKey(keyMap['RS'].invalidPublic);
          } else if (algPrefix === 'HS' ) {
            jwt.setSecret('bad secret');
          }

          jwt.verify(signData, function (verifyErr, verifyData) {
            if (v === 'NONE') {
              expect(verifyErr instanceof Error).to.be.false;
            } else {
              expect(verifyErr instanceof Error).to.be.true;
            }
            done();
          });
        });
      });

      it('should not verify with unparsable crypto header', function (done) {
        setupAlgorithm(v, jwt);
        jwt.sign(null, function (signErr, signData) {
          var parts = signData.split('.');
          parts[0] = parts[0].substr(3);
          signData = parts.join('.');

          jwt.verify(signData, function (verifyErr, verifyData) {
             expect(verifyErr instanceof JWT.JWTValidationError).to.be.true;
             done();
          });
        });
      });

      it('should not verify with unparsable claims header', function (done) {
        setupAlgorithm(v, jwt);
        jwt.sign(null, function (signErr, signData) {
          var parts = signData.split('.');
          parts[0] = parts[1].substr(3);
          signData = parts.join('.');

          jwt.verify(signData, function (verifyErr, verifyData) {
             expect(verifyErr instanceof JWT.JWTValidationError).to.be.true;
             done();
          });
        });
      });

      it('should not verify with unparsable signature header', function (done) {
        setupAlgorithm(v, jwt);
        jwt.sign(null, function (signErr, signData) {
          var parts = signData.split('.');
          parts[0] = parts[2].substr(3);
          signData = parts.join('.');

          jwt.verify(signData, function (verifyErr, verifyData) {
             expect(verifyErr instanceof JWT.JWTValidationError).to.be.true;
             done();
          });
        });
      });
    });

    describe('when validating claims with ' + v, function () {
      it('should process custom validation func() when enabled', function (done) {
        // Spy
        var spy = sinon.spy(function (claims, next) {
          next();
        });

        // Bootstrap instance
        setupAlgorithm(v, jwt);

        // Setup validations with custom hook
        jwt.setValidations({
          custom: spy
        });

        jwt.sign(null, function (signErr, signData) {
          jwt.verify(signData, function (verifyErr, verifyData) {
            expect(spy).to.be.spy;
            expect(spy).to.have.been.calledOnce;
            done();
          });
        });
      });

      it('should process custom validation func() err', function (done) {
        // Stub with fail
        var spy = sinon.spy(function (claims, next) {
          next(new JWT.JWTValidationError('test error'));
        });

        // Bootstrap instance
        setupAlgorithm(v, jwt);

        // Setup validations with custom hook
        jwt.setValidations({
          custom: spy
        });

        jwt.sign(null, function (signErr, signData) {
          jwt.verify(signData, function (verifyErr, verifyData) {
            expect(spy).to.be.spy;
            expect(spy).to.have.been.calledOnce;
            expect(verifyErr instanceof JWT.JWTValidationError).to.be.true;
            done();
          });
        });
      });

      it('should validate nbf when enabled', function (done) {
        setupAlgorithm(v, jwt);

        // Put 60 seconds into future
        jwt.setClaims({
          nbf: Math.floor(Date.now() / 1000) + 60
        });

        jwt.setValidations({
          nbf: true
        });

        // Check it errors
        jwt.sign(null, function (signErr, signData) {
          jwt.verify(signData, function (verifyErr, verifyData) {
            expect(verifyErr instanceof JWT.JWTInvalidBeforeTimeError).to.be.true;
            expect(verifyErr.invalidBefore).to.be.a('number');

            // Put 60 seconds into the past
            jwt.setClaims({
              nbf: Math.floor(Date.now() / 1000) - 60
            });

            jwt.sign(null, function (signErr, signData) {
              jwt.verify(signData, function (verifyErr, verifyData) {
                expect(verifyErr).to.be.null;
                expect(verifyData).to.be.a('object');
                done();
              });
            });
          });
        });
      });

      it('should process exp when enabled', function (done) {
        setupAlgorithm(v, jwt);

        // Put 60 seconds into the past
        jwt.setClaims({
          exp: Math.floor(Date.now() / 1000) - 60
        });

        jwt.setValidations({
          exp: true
        });

        // Check it errors
        jwt.sign(null, function (signErr, signData) {
          jwt.verify(signData, function (verifyErr, verifyData) {
            expect(verifyErr instanceof JWT.JWTExpiredError).to.be.true;
            expect(verifyErr.expiredAt).to.be.a('number');

            // Put 60 seconds into future
            jwt.setClaims({
              exp: Math.floor(Date.now() / 1000) + 60
            });

            jwt.sign(null, function (signErr, signData) {
              jwt.verify(signData, function (verifyErr, verifyData) {
                expect(verifyErr).to.be.null;
                expect(verifyData).to.be.a('object');
                done();
              });
            });
          });
        });
      });

      it('should process exp, nbf, custom when ALL enabled', function (done) {
        setupAlgorithm(v, jwt);

        // Spy for custom function
        var spy = sinon.spy(function (claims, next) {
          next();
        });

        // Make all passing
        jwt.setClaims({
          exp: Math.floor(Date.now() / 1000) + 60,
          nbf: Math.floor(Date.now() / 1000) - 60
        });

        jwt.setValidations({
          exp: true,
          nbf: true,
          custom: spy
        });

        jwt.sign(null, function (signErr, signData) {
          jwt.verify(signData, function (verifyErr, verifyData) {
            expect(spy).to.be.spy;
            expect(spy).to.have.been.calledOnce;
            expect(verifyErr).to.be.null;
            expect(verifyData).to.be.a('object');
            done();
          });
        });
      });
    });
  });
});

function setupAlgorithm (k, obj) {
  var algPrefix = k.substring(0,2);
  var algBitLength = k.substring(2,5)

  obj.setAlgorithm(k);

  if (algPrefix === 'RS') {
    obj.setPrivateKey(keyMap.RS.privateKey);
    obj.setPublicKey(keyMap.RS.publicKey);
  } else if (algPrefix === 'ES') {
    obj.setPrivateKey(keyMap['ES'+algBitLength].privateKey);
    obj.setPublicKey(keyMap['ES'+algBitLength].publicKey);
  } else if (algPrefix === 'HS') {
    obj.setSecret('test123');
  }
};
