/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
var async = require('async');
var bedrock = require('bedrock');
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var redis = require('bedrock-redis');
var BedrockError = bedrock.util.BedrockError;

// load config defaults
require('./config');

bedrock.events.on('bedrock-authn-did-jwt.config.secretStore', strategy => {
  strategy.setStore({
    sign: _sign,
    verify: _verify
  });
});

// FIXME: better way to inherit scope/algorithm from the strategy instance?
function _sign(scope) {
  return function(did, options, callback) {
    var algorithm = scope.token.algorithm;
    var tokenTtl = options.ttl;
    var keyTtl = tokenTtl + scope.token.clockToleranceInSecs;
    var secret = _generateHmacKey();
    async.auto({
      getKeyId: callback => {
        redis.client.incr('bedrock-jwt-key:id', callback);
      },
      storeKey: ['getKeyId', (callback, results) => {
        redis.client.setex(
          'bedrock-jwt-key:' + results.getKeyId, keyTtl, secret, callback);
      }],
      createToken: ['getKeyId', (callback, results) => {
        var nowInSecs = Math.floor(Date.now() / 1000);
        var notAfter = (nowInSecs + tokenTtl);
        jwt.sign({
          exp: notAfter,
          iat: nowInSecs,
          'urn:bedrock.authn': {
            did: did
          }
        }, secret, {
          algorithm: algorithm,
          header: {kid: results.getKeyId}
        }, (err, token) => {
          if(err) {
            return callback(new BedrockError(
              'Failed to generate JWT.', 'JwtFailure',
              {'public': false, httpStatusCode: 400}, err));
          }
          callback(null, token);
        });
      }]
    }, (err, results) => {
      if(err) {
        return callback(err);
      }
      callback(null, results.createToken);
    });
  };
}

// FIXME: better way to inherit scope/algorithm from the strategy instance?
function _verify(scope) {
  return function(token, options, callback) {
    try {
      var header = jwt.decode(token, {complete: true}).header;
    } catch(e) {
      return callback(e);
    }
    async.auto({
      getKey: callback => {
        redis.client.get('bedrock-jwt-key:' + header.kid, (err, result) => {
          if(err) {
            return callback(err);
          }
          if(!result) {
            return callback(new BedrockError(
              'InvalidKeyId', 'Invalid key identifier in token.'));
          }
          callback(null, result);
        });
      },
      verifyToken: ['getKey', (callback, results) => {
        // ensure algorithm matches by specifying `algorithms`
        jwt.verify(
          token, results.getKey, {algorithms: [scope.token.algorithm]},
          callback);
      }]
    }, (err, results) => {
      if(err) {
        return callback(err);
      }
      return callback(null, results.verifyToken);
    });
  };
}

function _generateHmacKey() {
  return crypto.randomBytes(16).toString('base64');
}
