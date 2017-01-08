/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const bedrock = require('bedrock');
const database = require('bedrock-mongodb');
const Store = require('./store');
// load config defaults
require('./config');

const api = {};
module.exports = api;

bedrock.events.on(
  'bedrock-authn-did-jwt.config.keyStore', (strategy, callback) =>
    strategy.setStore(new Store(), callback));

bedrock.events.on('bedrock-mongodb.ready', callback => {
  async.waterfall([
    callback => database.openCollections(['jwtKeyStore'], callback),
    callback => database.createIndexes([{
      collection: 'jwtKeyStore',
      fields: {id: 1},
      options: {unique: true, background: false}
    }], callback)
  ], callback);
});
