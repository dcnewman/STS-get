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
        logger.log(logger.INFO, `${lib.connId(conn)}: QUIT received; closing connection`);
        conn.end('+BYE\r\n');
        break;

      case 'VERSION':
        logger.log(logger.DEBUG, function() {
          return `${lib.connId(conn)}: VERSION received; sending version number ${version}`;
        });
        lib.send(conn, `+${version}\r\n`);
        break;

      default:
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

    dns.resolveTxt(host, function(err, data) {

      if (err) {
        logger.log(logger.DEBUG, function() {
          return `${lib.connId(opts.conn)}: dns.resolveTxt() error; err = ${err.message}`;
        });
        return reject(err);
      }

      if (_.isEmpty(data) || !Array.isArray(data)) {
        logger.log(logger.WARNING, function() {
          return `${lib.connId(opts.conn)}: Programming error? dns.resolveTxt() didn't return [][]?`;
        });
        return Promise.reject(new Error('EMPTY OR MISSING TXT RECORD'));
      }
      else if (data.length !== 1) {
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

  var tokens = tmp.replace(/\s/g, '').split(';');
  var i;
  for (i = 0; i < tokens.length; i++) {
    var nv = tokens[i].split('=');
    if (nv.length !== 2) {
      //
    }
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
  if (!('v' in opts) || !('id' in opts)) {
    logger.log(logger.DEBUG, function() {
      return `${lib.connId(opts.conn)}: ${opts.host} TXT RR lacks "v" or "id" values`;
    });
    return Promise.reject(new Error('INVALID TXT RR'));
  }
  logger.log(logger.DEBUG, function() {
    return `${lib.connId(opts.conn)}: ${opts.host} TXT RR v=${opts.v} and id=${opts.id}`;
  });
  return Promise.resolve(opts);
}

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

  return new Promise(function(resolve, reject) {
    var url = `http://mta-sts.${opts.host}/.well-known/mta-sts.txt`;
    logger.log(logger.DEBUG, function() {
      return `${lib.connId(opts.conn)}: getPolicy() performing HTTP GET of ${url}`;
    });
    request({
      url: url,
      method: 'GET',
      followRedirect: false,
      followAllRedirects: false,
      // strictSSL: true
    }, function (err, res, body) {
      if (err || _.isEmpty(res) || _.isEmpty(body)) {
        logger.log(logger.DEBUG, function() {
          return `${lib.connId(opts.conn)}: HTTP GET failed`;
        });
        return reject(new Error(`HTTP LOOKUP FAILED; ${err.message}`));
      }
      logger.log(logger.DEBUG, function() {
        return `${lib.connId(opts.conn)}: HTTP GET responsed with a status code of ${res.statusCode}`;
      });
      if (res.statusCode < 200 || res.statusCode >= 300) {
        return reject(new Error(`HTTP LOOKUP FAILED; ${res.statusCode}`));
      }
      return resolve(body);
    });
  });
}
