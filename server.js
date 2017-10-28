'use strict';

const dns = require('dns');
const net = require('net');
const request = require('request');
const _ = require('lodash');
const isFQDN = require('validator/lib/isFQDN');
const Promise = require('bluebird');

const PORT = process.env.PORT || 9000;
const ADDR = process.env.BIND || '0.0.0.0';

var server = net.createServer();
server.on('connection', handleConnection);
server.listen(PORT, ADDR, function() {
  var addrInfo = server.address();
  console.log(`server listening on ${addrInfo.address || '??'}:${addrInfo.port || '??'}`);
});

function handleConnection(conn) {

  conn.on('data', onConnData);
  conn.once('close', onConnClose);
  conn.on('error', onConnError);

  function onConnData(d) {

    d._sts = { msg: 'fooberry' };

    var data = d.toString();
    if (_.isEmpty(data) || !_.isString(data)) {
      // What to do
    }

    var tokens = data.trim().split(' ');
    var cmd = tokens[0].toUpperCase();
    switch (cmd) {

      case 'STS':
        if (tokens.length < 2) {
          conn.write('-MISSING DOMAIN NAME\r\n');
        }
        else if (!isFQDN(tokens[1], {require_tld: true, allow_underscores: false, allow_trailing_dot: false})) {
          conn.write('-INVALID DOMAIN NAME\r\n');
        }
        else {
          var opts = new Object();
          opts.host = tokens[1];
          return getTxt(opts)
            .then(validateTxt)
            .then(getPolicy)
            .then(function(str) {
              conn.write(str + '\r\n');
            })
            .catch(function(err) {
              conn.write('-' + err.message + '\r\n');
            });
        }
        break;

      case 'QUIT':
        conn.end('+BYE\r\n');
        break;

      case 'VERSION':
        conn.write('+0.1\r\n');
        break;

      default: break;
    }
  }

  function onConnClose(d) {
    console.log('Socket closed: msg=', d._sts ? d._sts.msg : '');
  }

  function onConnError(d) {
    conn.end('+BYE\r\n');
  }
}

function getTxt(opts) {
  if (_.isEmpty(opts) || _.isEmpty(opts.host)) {
    return Promise.reject(new Error('MISSING REQUIRED HOST'));
  }

  return new Promise(function(resolve, reject) {
    dns.resolveTxt(`_mta-sts.${opts.host}`, function(err, data) {
      if (err) {
        return reject(err);
      }
      opts.txt_rr = data.slice(0);
      return resolve(opts);
    });
  });
}

function validateTxt(opts) {
  if (_.isEmpty(opts) || _.isEmpty(opts.txt_rr)) {
    return Promise.reject(new Error('EMPTY OR MISSING TXT RECORD'));
  }
  else if (!Array.isArray(opts.txt_rr)) {
    return Promise.reject(new Error('EMPTY OR MISSING TXT RECORD'));
  }
  else if (opts.txt_rr.length !== 1) {
    return Promise.reject(new Error('EMPTY OR MISSING TXT RECORD'));
  }

  // dns.resolveTxt() returns an array of array!
  var tmp = opts.txt_rr[0].join('');
  if (_.isEmpty(tmp)) {
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
    return Promise.reject(new Error('-INVALID TXT RR'));
  }
  return Promise.resolve(opts);
}

function getPolicy(opts) {
  if (_.isEmpty(opts)) {
    // Some sort of programming error
    return Promise.reject(new Error('-PROGRAMMING ERROR?'));
  }

  var httpOpts = {
    url: `http://mta-sts.${opts.host}/.well-known/mta-sts.txt`,
    method: 'GET',
    followRedirect: false,
    followAllRedirects: false,
    // strictSSL: true
  };
  return new Promise(function(resolve, reject) {
    request(httpOpts, function (err, res, body) {
      if (err || _.isEmpty(res) || _.isEmpty(body)) {
        return reject(new Error(`-HTTP LOOKUP FAILED; ${err.message}`));
      }
      if (res.statusCode < 200 || res.statusCode >= 300) {
        return reject(new Error(`-HTTP LOOKUP FAILED; ${res.statusCode}`));
      }
      return resolve(body);
    });
  });
}
