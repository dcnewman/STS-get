'use strict';

var winston = require('winston');

// Use syslog levels
winston.setLevels(winston.config.syslog.levels);
winston.handleExceptions = true;
winston.emitErrs = false;
winston.exitOnErr = false;

// We use more traditional syslog values
const EMERG   = 0;
const ALERT   = 1;
const CRIT    = 2;  // aka, CRITICAL
const ERROR   = 3;  // aka, ERR
const WARNING = 4;
const NOTICE  = 5;
const INFO    = 6;
const DEBUG   = 7;

// For turning a string log level into a numeric value
const log_level_str = ['emerg', 'alert', 'crit', 'error', 'warning', 'notice', 'info', 'debug'];

// What logging level were we invoked with?
var level = process.env.LOG_LEVEL || 'info';
level = level.toLowerCase();

// Set our numeric value
var log_level = log_level_str.indexOf(level);
if (log_level < 0) {
  log_level = INFO;
}

// Log to the console
var logger = new (winston.Logger)({
    levels: winston.config.syslog.levels,
    level: level,
    handleExceptions: true,
    exitOnError: false,
    emitErrs: false,
    transports: [ new (winston.transports.Console)({timestamp: true}) ]
  });

// Log the message 'msg' if the logging level is <= 'level'
//  msg may be a function.  This permits not building the logging string
//  unless we know we will actually log the message.
//
// And yes, we only log strings (or functions which evaluate to a string)

function log(level, msg) {
  if (level > log_level)
    return;

  if (typeof(msg) === 'function')
    msg = msg();

  if (typeof(msg) !== 'string')
    return;

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
}

function logLevel(lvl) {
  var old_level = log_level;
  if (!isNaN(lvl) && 0 <= lvl && lvl < log_level_str.length) {
    winston.level = log_level_str[lvl];
    log_level = lvl;
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
