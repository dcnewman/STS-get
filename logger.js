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

var winston = require('winston');

// Use syslog levels
winston.setLevels(winston.config.syslog.levels);
winston.handleExceptions = true;
winston.emitErrs = false;
winston.exitOnErr = false;

// Traditional syslog levels for use by our callers
const EMERG   = 0;
const ALERT   = 1;
const CRIT    = 2;  // aka, CRITICAL
const ERROR   = 3;  // aka, ERR
const WARNING = 4;
const NOTICE  = 5;
const INFO    = 6;
const DEBUG   = 7;

// For turning a log level name into a numeric value
// We use lower case as Winston uses lower case
const log_level_str = ['emerg', 'alert', 'crit', 'error', 'warning', 'notice', 'info', 'debug'];

// What logging level were we invoked with?
var level = process.env.LOG_LEVEL || 'info';
level = level.toLowerCase();

// Set our numeric value
var log_level = log_level_str.indexOf(level);
if (log_level < 0) {
  log_level = INFO;
}

// Instantiate a logging context
//  presently we just log to the console
var logger = new (winston.Logger)(
  {
    levels: winston.config.syslog.levels,
    level: level,
    handleExceptions: true,
    exitOnError: false,
    emitErrs: false,
    transports: [ new (winston.transports.Console)({timestamp: true}) ]
  });

// Log the message 'msg' if the current logging level is <= 'level'.
//  msg may be a function.  This permits not building the logging string
//  unless we know we will actually log the message.
//
// And yes, we only log strings (or functions which evaluate to a string).

function log(level, msg) {

  if (level > log_level)
    // Return now and don't bother evaluating msg if it is a function
    return;

  if (typeof(msg) === 'function')
    msg = msg();

  if (typeof(msg) !== 'string')
    return;

  logger.log(log_level_str[level], msg);

  /*
  switch (level) {
  case EMERG:   logger.emerg(msg); return;
  case ALERT:   logger.alert(msg); return;
  case CRIT:    logger.crit(msg); return;
  case ERROR:   logger.error(msg); return;
  case WARNING: logger.warning(msg); return;
  case NOTICE:  logger.notice(msg); return;
  case INFO:    logger.info(msg); return;
  case DEBUG:   logger.debug(msg); return;
  default:      logger.info(msg); return;
  }
  */
}

// Set the logging level
function logLevel(lvl) {

  if (typeof(lvl) === 'string') {
    if (isNaN(lvl)) {
      lvl = log_level_str.indexOf(lvl.toLowerCase());
    }
    else {
      lvl = parseInt(lvl, 10);
    }
  }

  var old_level = log_level;
  if (0 <= lvl && lvl < log_level_str.length) {
    log_level = lvl;
    logger.transports.console.level = log_level_str[lvl];
  }
  return old_level;
}

module.exports = {
  log: log,
  logLevel: logLevel,
  EMERG: EMERG,
  ALERT: ALERT,
  CRIT: CRIT,
  CRITICAL: CRIT,
  ERROR: ERROR,
  ERR: ERROR,
  WARNING: WARNING,
  NOTICE: NOTICE,
  INFO: INFO,
  DEBUG: DEBUG
};
