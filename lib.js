'use strict';

// Each connection gets an id used for logging purposes
var connCounter = 0;

// Pad the integer m with enough leading zeros to create a string of length width
exports.pad = function(m, width) {
  return ('00000000000' + m).slice(-(width || 2));
};

// Default connection id to show when all else fails.
const defaultId = exports.pad(0, 8);

exports.nextId = function() {
  var id = exports.pad(connCounter, 8);
  connCounter += 1;
  return id;
};

// Return the connection's id for purposes of logging
exports.connId = function(conn) {
  if (typeof(conn) === 'object') {
    return conn && conn._sts ? conn._sts.id || defaultId : defaultId;
  }
  else if (typeof(conn) === 'string') {
    return conn;
  }
  return defaultId;
};

exports.sendError = function(conn, msg) {
  if (conn) {
    conn.write(`-${msg || 'error'}\r\n`);
  }
};
