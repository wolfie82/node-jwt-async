/*
 * jwt-async
 *
 * JSON Web Token (JWT) with asynchronicity
 *
 * Copyright(c) 2014 Patrick Baker <patricksbaker@gmail.com>
 * MIT Licensed
 */

var _ = require('lodash');

/**
 * Deep merges an object
 *
 */

_.mixin({
  defaultsDeep: function (a, b) {
    return _.partialRight(_.merge, function deep(value, other) {
      return _.merge(value, other, deep);
    })(a, b);
  }
});


module.exports = _;
