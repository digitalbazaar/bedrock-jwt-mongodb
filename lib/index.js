/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
// var _ = require('lodash');
var async = require('async');
var bedrock = require('bedrock');
// var config = bedrock.config;
var crypto = require('crypto');
var jwt = require('jsonwebtoken');
var redis = require('bedrock-redis');
var BedrockError = bedrock.util.BedrockError;

// load config defaults
require('./config');

// var logger = bedrock.loggers.get('app');

bedrock.events.on('bedrock-authn-did-jwt.config.secretStore', strategy => {
  strategy.setStore({
    sign: _sign,
    verify: _verify
  });
});

function _sign(did, options, callback) {
  var tokenTtl = options.ttl;
  // FIXME: how much longer than the token expiration should the key be kept?
  var keepKeySec = 60;
  var keyTtl = tokenTtl + keepKeySec;
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
      // FIXME: this is an option
      var notAfter = (nowInSecs + tokenTtl);
      jwt.sign({
        exp: notAfter,
        iat: nowInSecs,
        'urn:bedrock.authn': {
          did: did
        }
      }, secret, {
        algorithm: 'HS256', // FIXME: option
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
}

function _verify(token, options, callback) {
  var header = jwt.decode(token, {complete: true}).header;
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
      // FIXME: confirm algo is same
      jwt.verify(token, results.getKey, {}, callback);
    }]
  }, (err, results) => {
    if(err) {
      return callback(err);
    }
    return callback(null, results.verifyToken);
  });
}

function _generateHmacKey() {
  return crypto.randomBytes(16).toString('base64');
}
