'use strict'

validate = require './validate'

module.exports = (app) ->
  app.loopback.modelBuilder.mixins.define 'Validate', validate

  return
