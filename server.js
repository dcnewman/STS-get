// MIT License
//
// Copyright (c) 2017
// Dan Newman <dan.c.newman@icloud.com>, Ned Freed <ned.freed@mrochek.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

'use strict';

const version = '0.1';

const lib = require('./lib');
const logger = require('./logger');
const dns = require('dns');
const net = require('net');
const request = require('request');
const _ = require('lodash');
const isFQDN = require('validator/lib/isFQDN');
const Promise = require('bluebird');

// production or development environment/config?
const config = require(`./config.${process.env.NODE_ENV || 'development'}.js`);

// Set the logging level
logger.logLevel(config.logLevel);

// Stats
var stats = {
  time: { start: new Date(), up: 0 },
  connections: { open: 0, total: 0 },
  requests: { QUIT: 0, STATS: 0, STS: 0, VERSION: 0, bad: 0} ,
};

// Create our TCP server
var server = net.createServer();

server.on('error', function(err) {
  logger.log(logger.CRITICAL, `Cannot create server socket; ${err.message}`);
  throw err;
});

// Use handleConnection() to handle accepted sockets
server.on('connection', handleConnection);

// Log that we're listening...
server.listen(config.listenPort, config.bindAddr, function() {
  var addrInfo = server.address();
  logger.log(logger.NOTICE, `server listening on ${addrInfo.address || '??'}:${addrInfo.port || '??'}`);
});


// handleConnection is our primary routine for handling an inbound client connection
function handleConnection(conn) {

  stats.connections.open += 1;
  stats.connections.total += 1;

  var addrInfo = conn.address();
  var id = lib.nextId();
  conn._sts = { id: id };
  logger.log(logger.INFO, `${lib.connId(conn)}: New connection from ${addrInfo.address || '??'}:${addrInfo.port || '??'}`);

  conn.on('data', onConnData);
  conn.once('close', onConnClose);
  conn.on('error', onConnError);

  function onConnData(d) {

    var data = d.toString();
    if (_.isEmpty(data) || !_.isString(data)) {
      // TO DO
    }

    var tokens = data.trim().split(' ');
    var cmd = tokens[0].toUpperCase();
    switch (cmd) {

      case 'STS':
        stats.requests.STS += 1;
        if (tokens.length < 2) {
          logger.log(logger.DEBUG, function() {
            return `${lib.connId(conn)}: STS command received with no domain name`;
          });
          lib.sendError(conn, 'HOST MISSING');
        }
        else if (!isFQDN(tokens[1], {require_tld: true, allow_underscores: false, allow_trailing_dot: false})) {
          logger.log(logger.DEBUG, function() {
            return `${lib.connId(conn)}: STS command with invalid domain name`;
          });
          lib.sendError(conn, 'HOST INVALID');
        }
        else {
          logger.log(logger.DEBUG, function() {
            return `${lib.connId(conn)}: STS ${tokens[1]}`;
          });
          var opts = new Object();
          opts.conn = conn;
          opts.host = tokens[1];
          return getTxt(opts)
            .then(validateTxt)
            .then(getPolicy)
            .then(function(str) {
              // Ensure that the connection wasn't closed by a QUIT
              // command received whilst we were waiting on DNS and HTTP requests
              lib.send(conn, str);
            })
            .catch(function(err) {
              logger.log(logger.DEBUG, function() {
                return `${lib.connId(conn)}: STS command failed; err = ${err.message}`;
              });
              // Ensure that the connection wasn't closed by a QUIT
              // command received whilst we were waiting on DNS and HTTP requests
              if (!conn.destroyed) {
                lib.sendError(conn, err.message);
              }
            });
        }
        break;

      case 'QUIT':
        stats.requests.QUIT += 1;
        logger.log(logger.INFO, `${lib.connId(conn)}: QUIT received; closing connection`);
        conn.end('+BYE\r\n');
        stats.connections.open -= 1;
        break;

      case 'VERSION':
        stats.requests.VERSION += 1;
        logger.log(logger.DEBUG, function() {
          return `${lib.connId(conn)}: VERSION received; sending version number ${version}`;
        });
        lib.send(conn, `+${version}\r\n`);
        break;

      case 'STATS':
        stats.requests.STATS += 1;
        stats.time.up = Math.floor(((new Date()) - stats.time.start) / 1000);
        lib.send(conn, `+${JSON.stringify(stats)}\r\n`);
        break;

      default:
        stats.requests.bad += 1;
        logger.log(logger.DEBUG, function() {
          // Only log the first 10 chars of the command
          return `${lib.connId(conn)}: Unrecognized command received; ${cmd.substr(0, 10)}`;
        });
        lib.sendError(conn, 'UNKNOWN COMMAND');
        break;
    }
  }

  function onConnClose(d) {
    // conn is no longer valid
    logger.log(logger.INFO, `${lib.connId(id)}: Connection closed`);
  }

  function onConnError(err) {
    // ERR passed?
    logger.log(logger.WARNING, `${lib.connId(conn)}: Connection error; closing connection`);
    if (!conn.destroyed) {
      conn.end('+BYE\r\n');
      stats.connections.open -= 1;
    }
  }
}

// getTxt() -- Return a promise to perform a DNS TXT RR lookup
//   As we call dns.resolveTxt() and return its return value,
//   our resolution is a two-dimensional array.   We do not
//   validate the dns.resolveTxt() results here.  We leave that
//   to another routine in our promise chain.

function getTxt(opts) {

  // Sanity checks
  if (_.isEmpty(opts) || _.isEmpty(opts.host)) {
    logger.log(logger.WARNING, function() {
      return `${lib.connId(opts.conn)}: Programming error? getTxt() called with invalid call arguments`;
    });
    return Promise.reject(new Error('MISSING REQUIRED HOST'));
  }

  // Return a promise to lookup a TXT record for the host _mta-sts.<opts.host>
  return new Promise(function(resolve, reject) {

    var host = `_mta-sts.${opts.host}`;
    logger.log(logger.DEBUG, function() {
      return `${lib.connId(opts.conn)}: calling dns.resolveTxt(${host})`;
    });

    // Look for a TXT record
    dns.resolveTxt(host, function(err, data) {

      if (err) {
        logger.log(logger.DEBUG, function() {
          return `${lib.connId(opts.conn)}: dns.resolveTxt() error; err = ${err.code || err.message}`;
        });
        return reject(new Error(`FAILED TXT LOOKUP; ${err.code || err.message}`));
      }

      if (_.isEmpty(data) || !Array.isArray(data)) {
        // Should never happen....
        logger.log(logger.WARNING, function() {
          return `${lib.connId(opts.conn)}: Programming error? dns.resolveTxt() didn't return [][]?`;
        });
        return Promise.reject(new Error('EMPTY OR MISSING TXT RECORD'));
      }
      else if (data.length !== 1) {
        // More than one TXT RR?  Is the host name multi homed?
        logger.log(logger.DEBUG, function() {
          return `${lib.connId(opts.conn)}: dns.resolveHost(${host}) led to more than one TXT RR`;
        });
        return Promise.reject(new Error('EMPTY OR MISSING TXT RECORD'));
      }

      // Make a copy of the returned value and push it into the opts context
      opts.txt_rr = data.slice(0);

      logger.log(logger.DEBUG, function() {
        return `${lib.connId(opts.conn)}: dns.resolveTxt(${host}) returned ${opts.txt_rr}`;
      });

      // And return the opts context
      return resolve(opts);
    });
  });
}

// Parse and validate the obtained TXT RR
function validateTxt(opts) {

  if (_.isEmpty(opts) || _.isEmpty(opts.txt_rr)) {
    logger.log(logger.WARNING, function() {
      return `${lib.connId(opts.conn)}: Programming error? validateTxt() called with invalid call arguments`;
    });
    return Promise.reject(new Error('EMPTY OR MISSING TXT RECORD'));
  }

  // dns.resolveTxt() returns an array of array!
  var tmp = opts.txt_rr[0].join('');
  if (_.isEmpty(tmp)) {
    logger.log(logger.DEBUG, function() {
      return `${lib.connId(opts.conn)}: ${opts.host} led to an empty TXT RR`;
    });
    return Promise.reject(new Error('EMPTY OR MISSING TXT RECORD'));
  }

  // TXT RR should be a string of attribute=value pairs which
  // are delimited by semi colons.  Whitespace can be ignored.

  // Remove all whitespace and then split on ;
  var tokens = tmp.replace(/\s/g, '').split(';');

  // And now parse what we found

  // All we care about are v= and id= pairs
  // We here parse left to right.  And so if there are
  // multiple v= or id= pairs, we'll only note the right
  // most occurrence of any which is repeated.

  var i;
  for (i = 0; i < tokens.length; i++) {

    // Split name=value into name & value
    //   nv[0] is the name
    //   nv[1] is the value
    var nv = tokens[i].split('=');

    // Sanity checks
    if (nv.length < 2) {
      // TODO -- no '=' ???
      // For now, skip over
      continue;
    }
    else if (nv.length > 2) {
      // TODO -- treat as an error instead?
      // Hmm... multiple occurrences of '='
      // re-constitute nv[1],nv[2],... into a single string
      nv = [ nv[0], nv.slice(1).join('') ];
    }

    // Now handle the value based upon the name
    //   for now, treat the names as case insensitive
    switch (nv[0].toLowerCase()) {

      case 'v':
        if (nv[1].toLowerCase() === 'stsv1') {
          opts.v = 1;
        }
        break;

      case 'id':
        opts.id = nv[1];
        break;

      default:
        break;
    }
  }

  // Did we obtain both v and id values?
  // - If we have a v field, we know it must have been stsv1; otherwise,
  //     we would not have saved it.
  // - If we have an id value, it can be most anything

  if (!('v' in opts) || !('id' in opts)) {
    logger.log(logger.DEBUG, function() {
      return `${lib.connId(opts.conn)}: ${opts.host} TXT RR lacks "v" or "id" values`;
    });
    return Promise.reject(new Error('INVALID TXT RR'));
  }

  // All set to move on
  logger.log(logger.DEBUG, function() {
    return `${lib.connId(opts.conn)}: ${opts.host} TXT RR v=${opts.v} and id=${opts.id}`;
  });

  return Promise.resolve(opts);
}

// Perform an HTTPS GET to obtain the policy
//   We disallow redirects and require a valid SSL cert
function getPolicy(opts) {

  if (_.isEmpty(opts)) {
    // Some sort of programming error
    logger.log(logger.WARNING, function() {
      return `${lib.connId(opts.conn)}: Programming error? getPolicy() called with invalid call arguments`;
    });
    return Promise.reject(new Error('PROGRAMMING ERROR?'));
  }
  else if (opts.conn && opts.conn.destroyed) {
    // Don't bother with the HTTP request if the client has closed the connection
    logger.log(logger.DEBUG, function() {
      return `${lib.connId(opts.conn)}: Connection closed before getPolicy() invoked; terminating the promise chain`;
    });
    return Promise.reject(new ERROR('CLIENT CONNECTION CLOSED'));
  }

  // Promisify request.get()
  return new Promise(function(resolve, reject) {

    var url = `http://mta-sts.${opts.host}/.well-known/mta-sts.txt`;
    logger.log(logger.DEBUG, function() {
      return `${lib.connId(opts.conn)}: getPolicy() performing HTTP GET of ${url}`;
    });

    // Note that we will be subject to the operating system's connect timeout
    // here.  That is, we may be stuck for 2 minutes give or take.
    request({
      url: url,
      method: 'GET',
      followRedirect: false,
      followAllRedirects: false,
      // strictSSL: true
    }, function (err, res, body) {

      if (err) {
        logger.log(logger.DEBUG, function() {
          return `${lib.connId(opts.conn)}: HTTP GET failed; ${err.message}`;
        });
        return reject(new Error(`HTTP GET FAILED; ${err.message}`));
      }
      else if(_.isEmpty(res)) {
        // empty(res) should never occur
        logger.log(logger.DEBUG, function() {
          return `${lib.connId(opts.conn)}: HTTP GET failed; res is empty`;
        });
        return reject(new Error(`HTTP GET FAILED`));
      }

      logger.log(logger.DEBUG, function() {
        return `${lib.connId(opts.conn)}: HTTP GET responsed; status ${res.statusCode}`;
      });
      if (res.statusCode < 200 || res.statusCode >= 300) {
        return reject(new Error(`HTTP GET FAILED; ${res.statusCode}`));
      }
      return resolve(body || '');
    });
  });
}
