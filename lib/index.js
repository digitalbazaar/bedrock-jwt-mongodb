/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';
var _ = require('lodash');
var async = require('async');
var bedrock = require('bedrock');
// var config = bedrock.config;
var crypto = require('crypto');
var database = require('bedrock-mongodb');
var BedrockError = bedrock.util.BedrockError;

// load config defaults
require('./config');

var logger = bedrock.loggers.get('app');

var _proofState = null;

var api = {};
module.exports = api;

bedrock.events.on('bedrock-mongodb.ready', callback => {
  async.waterfall([
    callback => {
      database.openCollections(['jwt'], callback);
    },
    callback => {
      database.createIndexes([{
        collection: 'jwt',
        fields: {id: 1},
        options: {unique: true, background: false}
      }], callback);
    }], callback);
});

/**
 * Inserts the state information for a proof type.
 *
 * @param id the ID of the proof type.
 * @param state the new state information.
 * @param callback(err, record) called once the operation completes.
 */
api.insert = function(id, state, callback) {
  var now = Date.now();
  var record = {
    id: database.hash(id),
    meta: {
      created: now,
      updated: now
    },
    state: state
  };
  database.collections.jwt.insert(
    record, database.writeOptions, (err, result) => {
      if(err) {
        if(database.isDuplicateError(err)) {
          return callback(new BedrockError(
            'The proof state is a duplicate and could not be added.',
            'DuplicateProofState', {
              proof: id,
              httpStatusCode: 409,
              'public': true
            }));
        }
        logger.error('Mongo error when trying to insert proof state.', err);
        return callback(new BedrockError(
          'Failed to insert proof state due to internal error.',
          'InternalError',
          {proof: id, httpStatusCode: 500, 'public': true},
          err));
      }
      callback(null, result.ops[0]);
    });
};

/**
 * Updates the state information for a proof type.
 *
 * @param id the ID of the proof type.
 * @param state the new state information.
 * @param callback(err, updated) called once the operation completes.
 */
api.update = function(id, state, options, callback) {
  if(typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  var query = _.assign({}, options.query || {});
  query.id = database.hash(id);
  database.collections.jwt.update(
    query, {
      $set: {
        'meta.updated': Date.now(),
        'state': state
      }
    }, database.writeOptions, (err, result) => {
      if(err) {
        logger.error('Mongo error when trying to update proof state.', err);
        return callback(new BedrockError(
          'Failed to update proof state due to internal error.',
          'InternalError',
          {proof: id, httpStatusCode: 500, 'public': true},
          err));
      }
      callback(null, result.result.n > 0);
    });
};

/**
 * Gets the state information for a proof type.
 *
 * @param id the ID of the proof type.
 * @param callback(err, state, meta) called once the operation completes.
 */
api.get = function(id, callback) {
  database.collections.jwt.findOne(
    {id: database.hash(id)}, {state: true}, (err, record) => {
      if(err) {
        logger.error('Mongo error when trying to find proof state.', err);
        return callback(new BedrockError(
          'Failed to find proof state due to internal error.',
          'InternalError',
          {proof: id, httpStatusCode: 500, 'public': true}, err));
      }
      if(!record) {
        return callback(new BedrockError(
          'Proof state not found.',
          'NotFound',
          {proof: id, httpStatusCode: 404, 'public': true}));
      }
      callback(null, record.state, record.meta);
    });
};

/**
 * Gets the cached proof state information, retrieving it from the database
 * and recycling HMAC keys as needed.
 */
api.provision = function(options, callback) {
  var done = callback;
  const IDENTIFIER = options.identifier;
  const KEY_EXPIRATION = options.keyExpirationInSecs;
  async.auto({
    get: function(callback) {
      // use cached proof state if available, expiration checked later
      if(_proofState) {
        return callback(null, _proofState);
      }

      // get proof state from database
      api.get(IDENTIFIER, (err, state) => {
        if(err && err.name === 'NotFound') {
          return callback(null, null);
        }
        callback(err, state);
      });
    },
    ensureExists: ['get', function(callback, results) {
      if(results.get) {
        return callback(null, results.get);
      }
      // attempt to insert new state
      var nowInSecs = Math.floor(Date.now() / 1000);
      var state = {
        id: IDENTIFIER,
        previousKey: null,
        key: {
          id: '' + nowInSecs,
          algorithm: 'HS256',
          data: _generateHmacKey(),
          created: nowInSecs,
          expires: nowInSecs + KEY_EXPIRATION
        }
      };
      api.insert(IDENTIFIER, state, function(err) {
        if(err && err.name === 'DuplicateProofState') {
          // another process inserted; clear cache, loop, and try again
          _proofState = null;
          return process.nextTick(function() {
            api.provisioin(options, done);
          });
        }
        return callback(err, state);
      });
    }],
    update: ['ensureExists', function(callback, results) {
      var state = results.ensureExists;
      // Note: requires clock sync amongst auth.io nodes
      var nowInSecs = Math.floor(Date.now() / 1000);
      if(state.key.expires > nowInSecs) {
        // key not expired, nothing to do
        return callback(null, state);
      }
      // key expired, generate a new one
      state.previousKey = state.key;
      state.key = {
        id: '' + nowInSecs,
        algorithm: 'HS256',
        data: _generateHmacKey(),
        created: nowInSecs,
        expires: nowInSecs + KEY_EXPIRATION
      };
      logger.verbose('[proof-of-patience] recycling HMAC key...');
      api.update(IDENTIFIER, state, {
        query: {
          'state.key.id': state.previousKey.id
        }
      }, function(err, updated) {
        if(err) {
          logger.error(
            'Mongo error when trying to get proof-of-patience state.', err);
          return callback(err);
        }
        if(!updated) {
          // another process updated; clear cache, loop, and try again
          logger.verbose(
            '[proof-of-patience] another process recycled HMAC key.');
          _proofState = null;
          return process.nextTick(function() {
            api.provision(options, done);
          });
        }
        callback(null, state);
      });
    }],
    decode: ['update', function(callback, results) {
      var state = results.update;
      state.key.data = new Buffer(state.key.data, 'base64');
      if(state.previousKey) {
        state.previousKey.data = new Buffer(
          state.previousKey.data, 'base64');
      }
      // cache proof state
      _proofState = state;
      callback(null, state);
    }]
  }, function(err) {
    callback(err, _proofState);
  });
};

function _generateHmacKey() {
  return crypto.randomBytes(16).toString('base64');
}
