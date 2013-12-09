#!/usr/bin/env node

const crypto = require('crypto');
const express = require('express');
const https = require('https');
const openid = require('openid');

const CANONICAL_URL = process.env['CANONICAL_URL'] || 'http://localhost:3000';
const OPENID_IDENTIFIER = 'https://openid.fmarier.org';
const OPENID_STRICT_MODE = true;
const SESSION_SECRET = crypto.randomBytes(128) + '';

var app = express();

app.configure(function(){
  app.set('views', __dirname + '/views');
  app.use(express.cookieParser());
  app.use(express.session({ secret: SESSION_SECRET }));
  app.use(express.static(__dirname + '/public'));
});

var relyingParty = new openid.RelyingParty(CANONICAL_URL + '/verify', null, false,
                                           OPENID_STRICT_MODE, []);

app.get('/', function (req, res) {
  if (req.session.loggedin) {
    res.render('loggedin.ejs');
  } else {
    res.render('loggedout.ejs');
  }
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

app.get('/verify', function (req, res) {
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

app.listen(process.env['PORT'] || 3000, '127.0.0.1');
console.log('Application available at ' + CANONICAL_URL);
