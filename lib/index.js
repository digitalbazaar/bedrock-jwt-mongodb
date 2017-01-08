/*
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
const _ = require('lodash');
const async = require('async');
const bedrock = require('bedrock');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const database = require('bedrock-mongodb');
const BedrockError = bedrock.util.BedrockError;

let _keyState = null;

// load config defaults
require('./config');

const api = {};
module.exports = api;

const logger = bedrock.loggers.get('app');

// TODO: make responding to this event optional
bedrock.events.on(
  'bedrock-authn-did-jwt.config.secretStore', (strategy, callback) => {
    strategy.setStore(api, callback);
  });

bedrock.events.on('bedrock-mongodb.ready', callback => {
  async.waterfall([
    callback => {
      database.openCollections(['jwtKeyStore'], callback);
    },
    callback => {
      database.createIndexes([{
        collection: 'jwtKeyStore',
        fields: {id: 1},
        options: {unique: true, background: false}
      }], callback);
    }], callback);
});

/**
 * Initialize a namespaced keystore.
 *
 * @param options the options to use:
 *   algorithm the JWT signing algorithm to use.
 *   clockToleranceInSecs the clockTolerance to use in during JWT verification.
 *   namespace the namespace to use.
 *   provision true for provisioning operation.
 *   ttlInSecs the JWT ttl.
 * @param callback(err, state) called once the operation completes.
 */
api.provision = function(options, callback) {
  options = _.assign({}, options, {provision: true});
  _getState(options, err => callback(err));
};

/**
 * Create a JWT.
 *
 * @param options the options to use:
 *   namespace the namespace for the keystore.
 *   payload the payload to sign and include in the JWT.
 *
 * @param callback(err, state) called once the operation completes.
 */
api.sign = function(options, callback) {
  async.auto({
    getState: callback => {
      return _getState({namespace: options.namespace}, callback);
    },
    create: ['getState', (callback, results) => {
      const state = results.getState;
      const nowInSecs = Math.floor(Date.now() / 1000);
      const notAfter = (nowInSecs + state.tokenTtlInSecs);
      const payload = _.assign(
        {}, options.payload, {exp: notAfter, iat: nowInSecs});
      const token = jwt.sign(payload, state.key.data, {
        algorithm: state.algorithm,
        header: {kid: state.key.id}
      });

      callback(null, token);
    }]
  }, (err, results) => {
    callback(err, results ? results.create : null);
  });
};

/**
 * Verify a JWT.
 *
 * @param options the options to use:
 *   namespace the namespace for the keystore.
 *   token the token to be verified.
 *
 * @param callback(err, state) called once the operation completes.
 */
api.verify = function(options, callback) {
  async.auto({
    get: callback => {
      _getState({namespace: options.namespace}, callback);
    },
    verify: ['get', (callback, results) => {
      const state = results.get;
      let token;
      try {
        // parse header
        const header = jwt.decode(options.token, {complete: true}).header;

        // get key that matches key ID
        let key;
        if(header.kid === state.key.id) {
          key = state.key;
        } else if(state.previousKey && header.kid === state.previousKey.id) {
          key = state.previousKey;
        } else {
          throw new Error('Invalid key identifier in token.');
        }
        // decode and verify the token
        token = jwt.verify(
          options.token, key.data, {
            algorithms: [state.key.algorithm],
            clockTolerance: state.clockToleranceInSecs
          });
      } catch(e) {
        return callback(e, false);
      }
      callback(null, token);
    }]
  }, (err, results) => {
    callback(err, results ? results.verify : false);
  });
};

function _get(id, callback) {
  database.collections.jwtKeyStore.findOne(
    {id: database.hash(id)}, {state: true}, (err, record) => {
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
      callback(null, record.state, record.meta);
    });
}

function _insert(id, state, callback) {
  const now = Date.now();
  const record = {
    id: database.hash(id),
    meta: {
      created: now,
      updated: now
    },
    state: state
  };
  database.collections.jwtKeyStore.insert(
    record, database.writeOptions, (err, result) => {
      if(err) {
        if(database.isDuplicateError(err)) {
          return callback(new BedrockError(
            'The key state is a duplicate and could not be added.',
            'DuplicateRecord', {
              namespace: id,
              httpStatusCode: 409,
              'public': true
            }));
        }
        logger.error('Mongo error when trying to insert key state.', err);
        return callback(new BedrockError(
          'Failed to insert key state due to internal error.',
          'InternalError',
          {namespace: id, httpStatusCode: 500, 'public': true},
          err));
      }
      callback(null, result.ops[0]);
    });
}

function _update(id, state, options, callback) {
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
        'state': state
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

/**
 * Gets the cached key state information, retrieving it from the database
 * and recycling HMAC keys as needed.
 *
 * @param options the options to use:
 *   algorithm the JWT signing algorithm to use.
 *   clockToleranceInSecs the clockTolerance to use in during JWT verification.
 *   namespace the namespace to use.
 *   provision true for provisioning operation.
 *   ttlInSecs the JWT ttl.
 * @param callback(err, state) called once the operation completes.
 */
function _getState(options, callback) {
  const done = callback;
  async.auto({
    get: callback => {
      // use cached key state if available, expiration checked later
      if(_keyState) {
        return callback(null, _keyState);
      }
      // get key state from database
      _get(options.namespace, (err, state) => {
        if(err && err.name === 'NotFound' && options.provision) {
          return callback(null, null);
        }
        callback(err, state);
      });
    },
    ensureExists: ['get', (callback, results) => {
      if(results.get) {
        return callback(null, results.get);
      }
      // attempt to insert new state
      const nowInSecs = Math.floor(Date.now() / 1000);
      const state = {
        id: options.namespace,
        previousKey: null,
        tokenTtlInSecs: options.ttlInSecs,
        tokenClockToleranceInSecs: options.clockToleranceInSecs,
        key: {
          id: '' + nowInSecs,
          algorithm: options.algorithm,
          data: _generateHmacKey(),
          created: nowInSecs,
          expires: nowInSecs + options.ttlInSecs + options.clockToleranceInSecs
        }
      };
      _insert(options.namespace, state, err => {
        if(err && err.name === 'DuplicateRecord') {
          // another process inserted; clear cache, loop, and try again
          _keyState = null;
          return process.nextTick(() => {
            _getState(done);
          });
        }
        return callback(err, state);
      });
    }],
    update: ['ensureExists', (callback, results) => {
      const state = results.ensureExists;
      // NOTE: requires clock sync amongst nodes
      const nowInSecs = Math.floor(Date.now() / 1000);
      if(state.key.expires > nowInSecs) {
        // key not expired, nothing to do
        return callback(null, state);
      }
      // key expired, generate a new one
      state.previousKey = state.key;
      state.key = {
        id: '' + nowInSecs,
        algorithm: state.previousKey.algorithm,
        data: _generateHmacKey(),
        created: nowInSecs,
        expires: nowInSecs + state.tokeTtlInSecs +
          state.tokenClockToleranceInSecs
      };
      logger.verbose('[jwt-mongodb] recycling HMAC key...');
      _update(options.namespace, state, {
        query: {
          'state.key.id': state.previousKey.id
        }
      }, (err, updated) => {
        if(err) {
          logger.error(
            'Mongo error when trying to get key state.', err);
          return callback(err);
        }
        if(!updated) {
          // another process updated; clear cache, loop, and try again
          logger.verbose('[jwt-mongodb] another process recycled HMAC key.');
          _keyState = null;
          return process.nextTick(() => {
            _getState(done);
          });
        }
        callback(null, state);
      });
    }],
    decode: ['update', (callback, results) => {
      const state = results.update;
      state.key.data = new Buffer(state.key.data, 'base64');
      if(state.previousKey) {
        state.previousKey.data = new Buffer(
          state.previousKey.data, 'base64');
      }
      // cache key state
      _keyState = state;
      callback(null, state);
    }]
  }, err => {
    callback(err, _keyState);
  });
}

function _generateHmacKey() {
  return crypto.randomBytes(16).toString('base64');
}
