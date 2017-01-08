/*!
 * Copyright (c) 2017 Digital Bazaar, Inc. All rights reserved.
 */
const config = require('bedrock').config;
const path = require('path');

config.mocha.tests.push(path.join(__dirname, 'mocha'));

// MongoDB
config.mongodb.name = 'bedrock_jwt_mongodb_test';
config.mongodb.host = 'localhost';
config.mongodb.port = 27017;
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];
