'use strict';

module.exports = {
  debug: true,
  logLevel: process.env.LOG_LEVEL || 'DEBUG',
  listenPort: process.env.PORT || 9000,
  bindAddr: process.env.BIND || '0.0.0.0'
};
