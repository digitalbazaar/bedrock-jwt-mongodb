/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brKey = require('bedrock-key');
const BedrockError = bedrock.util.BedrockError;
const NamespaceHandler = require('./namespace-handler');

class NamespaceHandlerWebKey extends NamespaceHandler {

  createState(options, callback) {
    // all we need to do here is make sure the key is valid
    this.getKey(options, err => callback(err, {
      key: options.key
    }));
  }

  getKey(options, callback) {
    const key = options.key;
    brKey.getPublicKey(key, null, (err, publicKey, meta, privateKey) => {
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
      callback(
        null, {id: key.id, material: privateKey.privateKeyPem});
    });
  }
} // end class

module.exports = NamespaceHandlerWebKey;
