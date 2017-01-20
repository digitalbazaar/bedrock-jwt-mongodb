/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brKey = require('bedrock-key');
const BedrockError = bedrock.util.BedrockError;
const NamespaceHandler = require('./namespace-handler');

class NamespaceHandlerWebKey extends NamespaceHandler {
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
    // all we need to do here is make sure the key is valid
    this.getKey(options, err => callback(err, {}));
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
    const key = options.namespace.key;
    brKey.getPublicKey({id: key}, null, (err, publicKey, meta, privateKey) => {
      if(err) {
        return callback(new BedrockError('Invalid signing key specified.',
          'InvalidKey', {key: key}, err));
      }
      // ensure that the key has not been revoked
      if(publicKey.sysStatus !== 'active') {
        return callback(new BedrockError(
          'The specified signing key has been revoked.',
          'InvalidKey', {key: key}));
      }
      callback(null, {id: key, material: privateKey.privateKeyPem});
    });
  }
} // end class

module.exports = NamespaceHandlerWebKey;
