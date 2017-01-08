var brJwt = require('bedrock-jwt-mongodb');

describe('API', () => {
  it('should work', done => {
    brJwt.provision({
      identifier: 'alpha', keyExpirationInSecs: 30
    }, (err, result) => {
      console.log('RRRRRRRRRr', result);
      done();
    });
  });
});
