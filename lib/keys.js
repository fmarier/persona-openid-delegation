const jwcrypto = require('jwcrypto');
const cert = jwcrypto.cert;
require("jwcrypto/lib/algs/ds");
require("jwcrypto/lib/algs/rs");

const ISSUING_DOMAIN = process.env['ISSUING_DOMAIN'] || 'localhost';

var _pubKey;
var _secKey;

exports.pubKey = function (cb) {
  if (_pubKey) {
    return process.nextTick(function() {
      cb(null, _pubKey);
    });
  }

  // generate an ephemeral 1024 bit RSA key
  // TODO: generate a larger key
  jwcrypto.generateKeypair({
    algorithm: 'RS',
    keysize: 128
  }, function(err, keypair) {
    _pubKey = jwcrypto.loadPublicKey(keypair.publicKey.serialize());
    _secKey = jwcrypto.loadSecretKey(keypair.secretKey.serialize());
    cb(err, _pubKey);
  });
};

exports.cert_key = function(pubkey, email, duration_s, cb) {
  var now_ms = new Date();

  // TODO: enforce a maximum duration of 24h
  var assertionParams = {
    issuer: ISSUING_DOMAIN,
    issuedAt: now_ms,
    expiresAt: new Date(now_ms.valueOf() + duration_s * 1000)
  };
  var certParams = {
    publicKey: jwcrypto.loadPublicKey(JSON.stringify(pubkey)),
    principal: {
      email: email
    }
  };
  var additionalPayload = {};

  cert.sign(certParams, assertionParams, additionalPayload,
            _secKey, function(err, signedObject) {
    cb(err, signedObject);
  });
};
