'use strict';
var clone, debug, isObject, ref,
  hasProp = {}.hasOwnProperty;

ref = require('lodash'), isObject = ref.isObject, clone = ref.clone;

debug = require('debug')('loopback:mixins:validate');

module.exports = function(Model, options) {
  var addValidation, getFormatRegex, validation, validationMessages, validationName, validationTypes, validationnFormatTypes, validations, validationsObject;
  if (options == null) {
    options = {};
  }
  validations = Model.definition.settings.validations;
  validationMessages = function(expected) {
    return {
      presence: "can\"t be blank",
      absence: "can\"t be set",
      length: {
        min: "is too short (minimum is " + expected + " characters)",
        max: "is too long (maximum is " + expected + " characters)",
        is: "is not valid length (length is " + expected + " characters)"
      },
      numericality: {
        int: "is not an integer",
        number: "is not a number"
      },
      inclusion: "is not included in the list",
      exclusion: "is reserved",
      unique: "is not unique",
      format: "is not a valid " + expected + " format",
      required: "is required"
    };
  };
  validationTypes = function(validationName) {
    return {
      presense: function() {
        return Model.validatesPresenceOf(validationName);
      },
      length: function(validationConfig) {
        return Model.validatesLengthOf(validationName, validationConfig);
      },
      numericality: function(validationConfig) {
        return Model.validatesNumericalityOf(validationName, validationConfig);
      },
      inclusion: function(validationConfig) {
        return Model.validatesInclusionOf(validationName, validationConfig);
      },
      exclusion: function(validationConfig) {
        return Model.validatesExclusionOf(validationName, validationConfig);
      },
      format: function(validationConfig) {
        return Model.validatesFormatOf(validationName, validationConfig);
      },
      unique: function(validationConfig) {
        return Model.validatesUniquenessOf(validationName, validationConfig);
      },
      date: function(validationConfig) {
        return Model.validatesDateOf(validationName, validationConfig);
      }
    };
  };
  validationnFormatTypes = {
    color: /^#[a-z0-9]{6}|#[a-z0-9]{3}|(?:rgb\(\s*(?:[+-]?\d+%?)\s*,\s*(?:[+-]?\d+%?)\s*,\s*(?:[+-]?\d+%?)\s*\))aqua|black|blue|fuchsia|gray|green|lime|maroon|navy|olive|orange|purple|red|silver|teal|white|yellow$/i,
    date: /^\d{4}-\d{2}-\d{2}$/,
    dateTime: /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:.\d{1,3})?Z$/,
    digit: /[0-9]*$/,
    email: /^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.?$/i,
    empty: /^$/,
    float: /^[\-\+]?\b(\d+[.]\d+$)$/,
    hostName: /^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])/,
    integer: /^[\-\+]?[0-9]+$/,
    ip: /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/i,
    ipv6: /^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$/,
    letters: /[a-z][A-Z]*$/,
    luuid: /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i,
    numberFloat: /^[\-\+]?\b(\d+[.]\d+$)$/,
    numbers: /^\d+(\.\d{1,2})?$/,
    objectid: /^[0-9a-fA-F]{8}[0-9a-fA-F]{6}[0-9a-fA-F]{4}[0-9a-fA-F]{6}$/,
    time: /^\d{2}:\d{2}:\d{2}$/,
    timestamp: /^[0-9-]+,[\s]*[0-9-]+/,
    url: /((([A-Za-z]{3,9}:(?:\/\/)?)(?:[\-;:&=\+\$,\w]+@)?[A-Za-z0-9\.\-]+|(?:www\.|[\-;:&=\+\$,\w]+@)[A-Za-z0-9\.\-]+)((?:\/[\+~%\/\.\w\-_]*)?\??(?:[\-\+=&;%@\.\w_]*)#?(?:[\.\!\/\\\w]*))?)/,
    uuid: /[0-9a-f]{22}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i,
    uuid: /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i
  };
  getFormatRegex = function(validationConfig) {
    var format;
    format = validationConfig["with"] || validationConfig;
    return {
      formatName: format,
      formatRegex: validationnFormatTypes[format] || validationConfig["with"]
    };
  };
  if (!validations) {
    return;
  }
  validationsObject = validations[0] || validations;
  for (validationName in validationsObject) {
    if (!hasProp.call(validationsObject, validationName)) continue;
    validation = validationsObject[validationName];
    addValidation = function(validationType) {
      var configValue, formatName, formatRegex, message, msg, ref1, validationConfig;
      validationConfig = clone(validation[validationType]);
      if (validationType === 'format') {
        ref1 = getFormatRegex(validationConfig), formatName = ref1.formatName, formatRegex = ref1.formatRegex;
      }
      if (validationType === 'min' || validationType === 'max' || validationType === 'is') {
        configValue = validationConfig;
        if (!isObject(validationConfig)) {
          validationConfig = {};
        }
        validationConfig[validationType] = configValue;
        validationType = 'length';
      }
      msg = 'adding ' + validationType + ' validation (model: ' + Model.modelName + ', property: ' + validationName;
      if (!isObject(validationConfig)) {
        debug(msg + ', value: ' + validationConfig + ')');
        validationConfig = {};
      } else {
        debug(msg + ', config: ' + JSON.stringify(validationConfig) + ')');
      }
      if (!validationConfig.message) {
        message = validationMessages(configValue || formatName || validationConfig["with"] || validationConfig)[validationType];
        validationConfig.message = message || '';
      }
      if (formatRegex) {
        validationConfig["with"] = formatRegex;
      }
      validationConfig.allowNull = options.allowNull || true;
      validationConfig.allowBlank = options.allowBlank || true;
      return validationTypes(validationName)[validationType](validationConfig);
    };
    Object.keys(validation).forEach(addValidation);
  }
};
