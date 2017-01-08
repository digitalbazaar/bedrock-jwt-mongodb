/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const _ = require('lodash');
const async = require('async');
const bedrock = require('bedrock');
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const jwt = require('jsonwebtoken');
const BedrockError = bedrock.util.BedrockError;
const NamespaceHandler = require('./namespace-handler');

const logger = bedrock.loggers.get('app');

class NamespaceHandlerHmac extends NamespaceHandler {

  createState(options, callback) {
    const nowInSecs = Math.floor(Date.now() / 1000);
    const state = {
      previousKey: null,
      key: {
        id: '' + nowInSecs,
        data: this._generateHmacKey(),
        created: nowInSecs,
        expires: nowInSecs + options.tokenTtlInSecs +
          options.clockToleranceInSecs
      }
    };
    callback(null, state);
  }

  getKey(options, done) {
    const self = this;

    async.auto({
      getNamespace: callback => {
        if(typeof options.namespace !== 'string') {
          return callback(null, options);
        }
        self._get(options.namespace, callback);
      },
      rotate: ['getNamespace', (callback, results) => {
        const state = results.getNamespace;
        // NOTE: requires clock sync amongst nodes
        const nowInSecs = Math.floor(Date.now() / 1000);
        if(state.key.expires > nowInSecs) {
          // key not expired, nothing to rotate
          return callback(null, state);
        }
        // key expired, generate a new one
        state.previousKey = state.key;
        state.key = {
          id: '' + nowInSecs,
          data: self._generateHmacKey(),
          created: nowInSecs,
          expires: nowInSecs + state.tokenTtlInSecs +
            state.tokenClockToleranceInSecs
        };
        logger.verbose('[jwt-mongodb] recycling HMAC key...');
        self._update(options.namespace.id, state, {
          query: {
            'namespace.state.key.id': state.previousKey.id
          }
        }, (err, updated) => {
          if(err) {
            logger.error(
              'Mongo error when trying to get key state.', err);
            return callback(err);
          }
          if(!updated) {
            // another process updated; clear namespace, loop, and try again
            logger.verbose(
              '[jwt-mongodb] another process recycled HMAC key.');
            options = _.assign({}, options, {namespace: options.namespace.id});
            return process.nextTick(self.getKey.bind(self, options, done));
          }
          callback(null, state);
        });
      }],
      getKey: ['rotate', (callback, results) => {
        callback(null, {
          id: results.rotate.key.id,
          material: new Buffer(results.rotate.key.data, 'base64')
        });
      }]
    }, (err, results) => done(err, results ? results.getKey : null));
  }

  /**
   * Verify a JWT.
   *
   * @param token the token to be verified.
   * @param options the options to use:
   *   namespace the state to verify with.
   *   keyId the key ID to use.
   *
   * @param callback(err, tokenPayload) called once the operation completes.
   */
  verify(token, options, callback) {
    // get key that matches key ID
    const state = options.namespace.state;
    let key;
    if(options.keyId === state.key.id) {
      key = state.key;
    } else if(state.previousKey && options.keyId === state.previousKey.id) {
      key = state.previousKey;
    } else {
      return callback(new Error('Invalid key identifier in token.'));
    }
    // decode and verify the token
    jwt.verify(
      token, new Buffer(key.data, 'base64'), {
        clockTolerance: options.namespace.clockToleranceInSecs
      }, callback);
  }

  _get(id, callback) {
    database.collections.jwtKeyStore.findOne(
      {id: database.hash(id)}, {namespace: true}, (err, record) => {
        if(err) {
          logger.error('Mongo error when trying to find key state.', err);
          return callback(new BedrockError(
            'Failed to find key state due to internal error.',
            'InternalError',
            {key: id, httpStatusCode: 500, 'public': true}, err));
        }
        if(!record) {
          return callback(new BedrockError(
            'Key not found.',
            'NotFound',
            {key: id, httpStatusCode: 404, 'public': true}));
        }
        callback(null, record.namespace);
      });
  }

  _update(id, state, options, callback) {
    if(typeof options === 'function') {
      callback = options;
      options = {};
    }
    options = options || {};
    const query = _.assign({}, options.query || {});
    query.id = database.hash(id);
    database.collections.jwtKeyStore.update(
      query, {
        $set: {
          'meta.updated': Date.now(),
          'namespace.state': state
        }
      }, database.writeOptions, (err, result) => {
        if(err) {
          logger.error('Mongo error when trying to update key state.', err);
          return callback(new BedrockError(
            'Failed to update key state due to internal error.',
            'InternalError',
            {namespace: id, httpStatusCode: 500, 'public': true},
            err));
        }
        callback(null, result.result.n > 0);
      });
  }

  _generateHmacKey() {
    return crypto.randomBytes(16).toString('base64');
  }
} // end class

module.exports = NamespaceHandlerHmac;
