#!/usr/bin/env node

const crypto = require('crypto');
const ejs = require('ejs');
const express = require('express');
const fs = require('fs');
const https = require('https');
const openid = require('openid');

const keys = require('./lib/keys');

const CANONICAL_URL = process.env['CANONICAL_URL'] || 'http://localhost:3000';
const EMAIL = 'francois@browserid.fmarier.org';
const OPENID_IDENTIFIER = 'https://openid.fmarier.org';
const OPENID_STRICT_MODE = true;
const SESSION_SECRET = crypto.randomBytes(128) + '';

var app = express();
app.configure(function(){
  app.set('views', __dirname + '/views');
  app.use(express.cookieParser());
  app.use(express.session({ secret: SESSION_SECRET, cookie: { secure: true } }));

  app.use(function(req, res, next) {
    if (req.path === '/.well-known/browserid') {
      res.setHeader('Content-Type', 'application/json');
    }
    next();
  });

  app.use(express.static(__dirname + '/public'));
  app.use(express.json());
});

var relyingParty = new openid.RelyingParty(CANONICAL_URL + '/api/openid_verify', null, false,
                                           OPENID_STRICT_MODE, []);

app.get('/', function (req, res) {
  if (req.session.loggedin) {
    res.render('loggedin.ejs');
  } else {
    res.render('loggedout.ejs');
  }
});

app.post('/api/cert_key', function(req, res) {
  if (!req.session.loggedin) {
    res.writeHead(401);
    return res.end();
  }
  if (!req.body.pubkey || !req.body.duration) {
    res.writeHead(400);
    return res.end('missing parameters');
  }

  keys.cert_key(req.body.pubkey, EMAIL, req.body.duration, function(err, cert) {
    if (err) {
      res.writeHead(500);
      res.end();
    } else {
      res.json({ cert: cert });
    }
  });
});

app.get('/api/loggedin', function (req, res) {
  if (req.session.loggedin) {
    res.json(200, true);
  } else {
    res.json(401, false);
  }
});

app.get('/api/openid_verify', function (req, res) {
  relyingParty.verifyAssertion(req, function(error, result) {
    if (error) {
      res.writeHead(200);
      res.end('Authentication failed: ' + error.message);
    } else if (result.authenticated === true &&
              result.claimedIdentifier === OPENID_IDENTIFIER) {
      req.session.loggedin = true;
      res.redirect('/');
    } else {
      req.session.loggedin = false;
      res.end('Authentication failed');
    }
  });
});

app.get('/login', function (req, res) {
  if (req.session.loggedin) {
    res.render('index.ejs');
  } else {
    relyingParty.authenticate(OPENID_IDENTIFIER, false, function(error, authUrl) {
      if (error) {
        res.writeHead(200);
        res.end('Authentication failed: ' + error.message);
      } else if (!authUrl) {
        res.writeHead(200);
        res.end('Authentication failed');
      } else {
        res.redirect(302, authUrl);
      }
    });
  }
});

app.get('/logout', function (req, res) {
  req.session.loggedin = false;
  res.redirect('/');
});

const WELL_KNOWN_PATH = __dirname + '/public/.well-known';
keys.pubKey(function (err, pubkey) {
  ejs.renderFile(__dirname + '/views/browserid.ejs', {
    pubKey: JSON.parse(pubkey.serialize())
  }, function(err, r) {
    if (err) {
      throw err;
    }
    try {
      fs.mkdirSync(WELL_KNOWN_PATH);
    } catch(e) {
    }
    var p = WELL_KNOWN_PATH + '/browserid';
    try {
      fs.unlinkSync(p);
    } catch(e) {
    }
    fs.writeFileSync(p, r);
  });
});

app.listen(process.env['PORT'] || 3000, '127.0.0.1');
console.log('Application available at ' + CANONICAL_URL);
