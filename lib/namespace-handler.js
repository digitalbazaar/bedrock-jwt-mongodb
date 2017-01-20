/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const _ = require('lodash');
const async = require('async');
const bedrock = require('bedrock');
const jwt = require('jsonwebtoken');

class NamespaceHandler {
  /**
   * Creates any custom state information for the given namespace during
   * provisioning.
   *
   * @param options the options to use:
   *   namespace the namespace:
   *     id the identifier for the namespace.
   *     algorithm the JWT signing algorithm.
   *     tokenTtlInSecs the JWT token TTL.
   *     state any custom namespace state.
   *     [key] an optional key identifier for this namespace.
   * @param callback(err, state) called once the operation completes.
   */
  createState(options, callback) {
    callback(new Error(
      'NamespaceHandler#createState must be overriden by subclass.'));
  }

  /**
   * Gets a key from the given options (or elsewhere).
   *
   * @param options the options to use:
   *   namespace the namespace:
   *     id the identifier for the namespace.
   *     algorithm the JWT signing algorithm.
   *     tokenTtlInSecs the JWT token TTL.
   *     state any custom namespace state.
   *     [key] an optional key identifier for this namespace.
   * @param callback(err, {id: keyId, material: keyMaterial}) called
   *   once the operation completes.
   */
  getKey(options, callback) {
    callback(new Error(
      'NamespaceHandler#getKey must be overriden by subclass.'));
  }

  /**
   * Verifies a JWT.
   *
   * @param token the token to be verified.
   * @param options the options to use:
   *   namespace the namespace to verify with.
   *   keyId the namespace-specific key ID to use, parsed from the token's
   *     `kid` value (any namespace identifier in the `kid` has been removed).
   * @param callback(err, tokenPayload) called once the operation completes.
   */
  verify(token, options, callback) {
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
   *     [key] an optional key identifier for this namespace.
   *   payload the payload to sign and include in the JWT.
   *
   * @param callback(err, token) called once the operation completes.
   */
  sign(options, callback) {
    const self = this;
    const payload = bedrock.util.clone(options.payload);
    async.auto({
      getKey: self.getKey.bind(self, {namespace: options.namespace}),
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
