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

// Each connection gets an id used for logging purposes
var connCounter = 0;

// Pad the integer m with enough leading zeros to create a string of length width
exports.pad = function(m, width) {
  return ('00000000000' + m).slice(-(width || 2));
};

// Default connection id to show when all else fails.
const defaultId = exports.pad(0, 8);

// Generate a connection id from connCounter
exports.nextId = function() {
  return exports.pad(connCounter++, 8);
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

// Send msg to the client; assumes \r\n already present
exports.send = function(conn, msg) {
  if (conn && !conn.destroyed) {
    conn.write(msg);
  }
};

// Send error to the client; assumes \r\n must be appended
exports.sendError = function(conn, msg) {
  if (conn && !conn.destroyed) {
    conn.write(`-${msg || 'error'}\r\n`);
  }
};
