'use strict';

const version = '0.1';

const dns = require('dns');
const net = require('net');
const request = require('request');
const _ = require('lodash');
const isFQDN = require('validator/lib/isFQDN');
const Promise = require('bluebird');
const logger = require('./logger');

logger.logLevel(logger.DEBUG);

const listenPort = process.env.PORT || 9000;
const bindAddr = process.env.BIND || '0.0.0.0';

var connCounter = 0;

// Create our TCP server
var server = net.createServer();

// Use handleConnection() to handle accepted sockets
server.on('connection', handleConnection);

// Log that we're listening...
server.listen(listenPort, bindAddr, function() {
  var addrInfo = server.address();
  logger.log(logger.NOTICE, `server listening on ${addrInfo.address || '??'}:${addrInfo.port || '??'}`);
});

function sendError(conn, msg) {
  if (conn) {
    conn.write(`-${msg || error}\r\n`);
  }
}

function pad(m, width) {
  return ('00000000000' + m).slice(-(width || 2));
}

const defaultId = pad(0, 8);

function connId(conn) {
  if (typeof(conn) === 'object') {
    return conn && conn._sts ? conn._sts.id || defaultId : defaultId;
  }
  else if (typeof(conn) === 'string') {
    return conn;
  }
  return defaultId;
}

function handleConnection(conn) {

  var addrInfo = conn.address();
  var id = pad(connCounter, 8);
  conn._sts = { id: id };
  connCounter += 1;
  logger.log(logger.INFO, `${connId(conn)}: New connection from ${addrInfo.address || '??'}:${addrInfo.port || '??'}`);

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
            return `${connId(conn)}: STS command with no domain name`;
          });
          sendError(conn, 'MISSING DOMAIN NAME');
        }
        else if (!isFQDN(tokens[1], {require_tld: true, allow_underscores: false, allow_trailing_dot: false})) {
          logger.log(logger.DEBUG, function() {
            return `${connId(conn)}: STS command with invalid domain name`;
          });
          sendError(conn, 'INVALID DOMAIN NAME');
        }
        else {
          logger.log(logger.DEBUG, function() {
            return `${connId(conn)}: STS ${tokens[1]}`;
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
              if (!conn.destroyed) {
                conn.write(str);
              }
            })
            .catch(function(err) {
              logger.log(logger.DEBUG, function() {
                return `${connId(conn)}: STS command failed; err = ${err.message}`;
              });
              // Ensure that the connection wasn't closed by a QUIT
              // command received whilst we were waiting on DNS and HTTP requests
              if (!conn.destroyed) {
                sendError(conn, err.message);
              }
            });
        }
        break;

      case 'QUIT':
        conn.end('+BYE\r\n');
        break;

      case 'VERSION':
        conn.write(version + '\r\n');
        break;

      default: break;
    }
  }

  function onConnClose(d) {
    // conn is no longer valid
    logger.log(logger.INFO, `${connId(id)}: Connection closed`);
  }

  function onConnError(err) {
    // ERR passed?
    logger.log(logger.WARNING, `${connId(conn)}: Connection error; closing connection`);
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
      return `${connId(opts.conn)}: Programming error? getTxt() called with invalid call arguments`;
    });
    return Promise.reject(new Error('MISSING REQUIRED HOST'));
  }

  // Return a promise to lookup a TXT record for the host _mta-sts.<opts.host>
  return new Promise(function(resolve, reject) {

    var host = `_mta-sts.${opts.host}`;
    logger.log(logger.DEBUG, function() {
      return `${connId(opts.conn)}: calling dns.resolveTxt(${host})`;
    });

    dns.resolveTxt(host, function(err, data) {

      if (err) {
        logger.log(logger.DEBUG, function() {
          return `${connId(opts.conn)}: dns.resolveTxt() error; err = ${err.message}`;
        });
        return reject(err);
      }

      // Make a copy of the returned value and push it into the opts context
      opts.txt_rr = data.slice(0);

      logger.log(logger.DEBUG, function() {
        return `${connId(opts.conn)}: dns.resolveTxt(${host}) returned ${opts.txt_rr}`;
      });

      // And return the opts context
      return resolve(opts);
    });
  });
}

function validateTxt(opts) {
  
  if (_.isEmpty(opts) || _.isEmpty(opts.txt_rr)) {
    logger.log(logger.WARNING, function() {
      return `${connId(opts.conn)}: Programming error? validateTxt() called with invalid call arguments`;
    });
    return Promise.reject(new Error('EMPTY OR MISSING TXT RECORD'));
  }
  else if (!Array.isArray(opts.txt_rr)) {
    logger.log(logger.WARNING, function() {
      return `${connId(opts.conn)}: Programming error? dns.resolveTxt() didn't return [][]?`;
    });
    return Promise.reject(new Error('EMPTY OR MISSING TXT RECORD'));
  }
  else if (opts.txt_rr.length !== 1) {
    logger.log(logger.DEBUG, function() {
      return `${connId(opts.conn)}: ${opts.host} led to more than one TXT RR`;
    });
    return Promise.reject(new Error('EMPTY OR MISSING TXT RECORD'));
  }

  // dns.resolveTxt() returns an array of array!
  var tmp = opts.txt_rr[0].join('');
  if (_.isEmpty(tmp)) {
    logger.log(logger.DEBUG, function() {
      return `${connId(opts.conn)}: ${opts.host} led to an empty TXT RR`;
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
      return `${connId(opts.conn)}: ${opts.host} TXT RR lacks "v" or "id" values`;
    });
    return Promise.reject(new Error('INVALID TXT RR'));
  }
  logger.log(logger.DEBUG, function() {
    return `${connId(opts.conn)}: ${opts.host} TXT RR v=${opts.v} and id=${opts.id}`;
  });
  return Promise.resolve(opts);
}

function getPolicy(opts) {
  if (_.isEmpty(opts)) {
    // Some sort of programming error
    return Promise.reject(new Error('PROGRAMMING ERROR?'));
  }

  return new Promise(function(resolve, reject) {
    request({
      url: `http://mta-sts.${opts.host}/.well-known/mta-sts.txt`,
      method: 'GET',
      followRedirect: false,
      followAllRedirects: false,
      // strictSSL: true
    }, function (err, res, body) {
      if (err || _.isEmpty(res) || _.isEmpty(body)) {
        return reject(new Error(`HTTP LOOKUP FAILED; ${err.message}`));
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        return reject(new Error(`HTTP LOOKUP FAILED; ${res.statusCode}`));
      }
      return resolve(body);
    });
  });
}
