'use strict';
var validate;

validate = require('./validate');

module.exports = function(app) {
  app.loopback.modelBuilder.mixins.define('Validate', validate);
};
