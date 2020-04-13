// Node imports
const { inherits } = require('util')
// Auth imports
const AppleSignInStrategy = require('./sign-in-strategy')

/** @typedef { import('./types.d').StrategyOptions } StrategyOptions */

/**
 * @param {StrategyOptions} options
 * @param {function} [verify]
 * @constructor
 */
function AppleTokenStrategy(options, verify) {
  AppleSignInStrategy.call(this, options, verify)
  this.name = 'apple-token'
}

inherits(AppleTokenStrategy, AppleSignInStrategy)

AppleTokenStrategy.prototype.authenticate = function (req, options) {
  if (req.method !== 'POST' || !req.body) {
    return this.fail({ message: 'POST request with body required' })
  }
  if (!req.body.code) {
    return this.fail({ message: '`code` is required' })
  }
  AppleSignInStrategy.prototype.authenticate.call(this, req, options)
}

module.exports = AppleTokenStrategy
