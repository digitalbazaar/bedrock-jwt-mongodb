/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const bedrock = require('bedrock');
const database = require('bedrock-mongodb');
const jwt = require('jsonwebtoken');
const BedrockError = bedrock.util.BedrockError;
const NamespaceHandlerWebKey = require('./namespace-handler-web-key');
const NamespaceHandlerHmac = require('./namespace-handler-hmac');

const logger = bedrock.loggers.get('app');

class Store {
  constructor() {
    const handlerWebKey = new NamespaceHandlerWebKey();
    this.handlers = {
      HS: new NamespaceHandlerHmac(),
      RS: handlerWebKey
      // TODO: Add ECDSA support
      // ES: handlerWebKey
    };
  }

  getNamespace(id, callback) {
    database.collections.jwtKeyStore.findOne(
      {id: database.hash(id)}, {namespace: true}, (err, record) => {
        if(err) {
          logger.error('Mongo error when trying to find key state.', err);
          return callback(new BedrockError(
            'Failed to find key state due to internal error.',
            'InternalError',
            {namespace: id, httpStatusCode: 500, 'public': true}, err));
        }
        if(!record) {
          return callback(new BedrockError(
            'Key state not found.',
            'NotFound',
            {namespace: id, httpStatusCode: 404, 'public': true}));
        }
        callback(null, record.namespace);
      });
  }

  /**
   * Initialize a namespaced keystore.
   *
   * @param namespace the namespace to initialize.
   * @param options the options to use:
   *   id the ID for the namespace.
   *   algorithm the JWT signing algorithm.
   *   clockToleranceInSecs the acceptable clock skew.
   *   tokenTtlInSecs the JWT token TTL.
   *   [key] the key options:
   *     id the key ID.
   *
   * @param callback(err) called once the operation completes.
   */
  provision(options, callback) {
    const self = this;
    let handler;
    try {
      handler = self._getNamespaceHandler(options.algorithm);
    } catch(e) {
      return callback(new BedrockError(
        'Unsupported algorithm.', 'NotFound',
        {public: false, namespace: options}));
    }
    async.auto({
      createState: handler.createState.bind(handler, options),
      storeNamespace: ['createState', (callback, results) => {
        const now = Date.now();
        const record = {
          id: database.hash(options.id),
          meta: {
            created: now,
            updated: now
          },
          namespace: {
            id: options.id,
            algorithm: options.algorithm,
            clockToleranceInSecs: options.clockToleranceInSecs,
            tokenTtlInSecs: options.tokenTtlInSecs,
            state: results.createState
          }
        };
        database.collections.jwtKeyStore.insert(
          record, database.writeOptions, (err, result) => {
            if(err) {
              if(database.isDuplicateError(err)) {
                // namespace is already provisioned
                // TODO: ensure record in database matches given options
                return callback();
              }
              logger.error(
                '[jwt-mongodb] Mongo error when trying to insert namespace.',
                err);
              return callback(new BedrockError(
                'Failed to insert namespace due to internal error.',
                'InternalError',
                {namespace: options.id, httpStatusCode: 500, 'public': true},
                err));
            }
            callback(null, result.ops[0]);
          });
      }]
    }, callback);
  }

  /**
   * Create a JWT.
   *
   * @param options the options to use:
   *   namespace the namespace to use for the signing operation.
   *   payload the payload to be included in the JWT.
   * @param callback(err, token) called once the operation completes.
   */
  sign(options, callback) {
    const self = this;
    async.auto({
      getNamespace: self.getNamespace.bind(self, options.namespace),
      sign: ['getNamespace', (callback, results) => {
        let handler;
        try {
          handler = self._getNamespaceHandler(results.getNamespace.algorithm);
        } catch(e) {
          return callback(e);
        }
        handler.sign({
          namespace: results.getNamespace,
          payload: options.payload
        }, callback);
      }]
    }, (err, results) => callback(err, results ? results.sign : null));
  }

  verify(token, callback) {
    let header;
    let decodedToken;
    try {
      decodedToken = jwt.decode(token, {complete: true});
      header = decodedToken.header;
    } catch(err) {
      return callback(err);
    }

    if(!header.alg.startsWith('HS')) {
      return callback(null, new Error('Unsupported algorithm.'));
    }

    const self = this;
    const parsedKid = self._parse(header.kid);

    async.auto({
      getNamespace: callback =>
        self.getNamespace(parsedKid.namespace, callback),
      verify: ['getNamespace', (callback, results) => {
        let handler;
        try {
          handler = self._getNamespaceHandler(results.getNamespace.algorithm);
        } catch(e) {
          return callback(e);
        }
        handler.verify(
          token, {
            namespace: results.getNamespace,
            keyId: parsedKid.keyId
          }, callback);
      }]
    }, (err, results) => callback(err, results ? results.verify : null));
  }

  _parse(kid) {
    const parts = kid.split(':');
    return {
      namespace: parts[0],
      keyId: parts[1]
    };
  }

  _getNamespaceHandler(algorithm) {
    const handler = this.handlers[algorithm.substr(0, 2)];
    if(!handler) {
      throw new Error('Unsupported algorithm.');
    }
    return handler;
  }
}

module.exports = Store;
