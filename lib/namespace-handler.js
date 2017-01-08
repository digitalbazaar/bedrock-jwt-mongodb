/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const _ = require('lodash');
const async = require('async');
const bedrock = require('bedrock');
const jwt = require('jsonwebtoken');

class NamespaceHandler {

  createState(options, callback) {
    callback(new Error(
      'NamespaceHandler#createState must be overriden by subclass.'));
  }

  getKey(state, callback) {
    callback(new Error(
      'NamespaceHandler#getKey must be overriden by subclass.'));
  }

  verify(options, callback) {
    callback(new Error(
      'NamespaceHandler#verify must be overriden by subclass.'));
  }

  /**
   * Create a JWT.
   *
   * @param options the options to use:
   *   namespace the namespace:
   *     id the identifier for the namespace.
   *     algorithm the JWT signing algorithm.
   *     tokenTtlInSecs the JWT token TTL.
   *     state any custom namespace state.
   *   payload the payload to sign and include in the JWT.
   *
   * @param callback(err, token) called once the operation completes.
   */
  sign(options, callback) {
    const self = this;
    const payload = bedrock.util.clone(options.payload);
    async.auto({
      getKey: self.getKey.bind(self, options.namespace.state),
      create: ['getKey', (callback, results) => {
        const key = results.getKey;
        const nowInSecs = Math.floor(Date.now() / 1000);
        const notAfter = (nowInSecs + options.namespace.tokenTtlInSecs);
        _.assign(payload, {exp: notAfter, iat: nowInSecs});
        const token = jwt.sign(payload, key.material, {
          algorithm: options.namespace.algorithm,
          header: {
            kid: options.namespace.algorithm.startsWith('HS') ?
              (options.namespace.id + ':' + key.id) : key.id
          }
        });
        return callback(null, token);
      }]
    }, (err, results) => callback(err, results ? results.create : null));
  }
}

module.exports = NamespaceHandler;
