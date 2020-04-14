// Node imports
const { inherits } = require('util')
// NPM imports
const OAuth2Strategy = require('passport-oauth2')
// Auth imports
const {
  AUTHORIZATION_URL,
  TOKEN_URL,
  createClientSecretGenerator,
  createIdentityTokenValidator
} = require('./utils')

/** @typedef { import('./types.d').StrategyOptions } StrategyOptions */

/**
 * @param {StrategyOptions} options
 * @param {function} [verify]
 * @constructor
 */
function AppleSignInStrategy(_options, _verify) {
  const options = AppleSignInStrategy.normalizeOptions(_options)
  const verify = AppleSignInStrategy.normalizeVerify(_options, _verify)

  OAuth2Strategy.call(this, options, verify)
  this.name = 'apple'

  // Wrap `getOAuthAccessToken` to generate `clientSecret` for every call
  this._wrapOAuthGetAccessToken(options)
}

inherits(AppleSignInStrategy, OAuth2Strategy)

/**
 * @param {Express.Request} req
 * @param {any} options
 * @returns {void}
 */
AppleSignInStrategy.prototype.authenticate = function (req, options) {
  // Copy body fields to query so that OAuth2Strategy respects `form_post` data
  req.query = { ...req.body, ...req.query }
  /**
   * Currently, the only error code returned is `user_cancelled_authorize`.
   * This error code is returned when the user clicks the "Cancel" button during the web flow.
   * @see https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/configuring_your_webpage_for_sign_in_with_apple
   */
  if (req.query.error === 'user_cancelled_authorize') {
    return this.fail({ message: 'User cancelled authorization' })
  }
  OAuth2Strategy.prototype.authenticate.call(this, req, options)
}

AppleSignInStrategy.prototype.authorizationParams = function (options) {
  return {
    // If `scope` is specified, `response_mode` MUST BE `form_post`
    'response_mode': (options.scope || this._scope) ? 'form_post' : 'query'
  }
}

/**
 * @param {StrategyOptions} options
 * @returns {void}
 */
AppleSignInStrategy.prototype._wrapOAuthGetAccessToken = function (options) {
  const generateClientSecret = createClientSecretGenerator(options)

  const oauth2 = this._oauth2
  const originalGetOAuthAccessToken = oauth2.getOAuthAccessToken
  oauth2.getOAuthAccessToken = wrappedGetOAuthAccessToken

  function wrappedGetOAuthAccessToken(code, params, callback) {
    generateClientSecret((err, clientSecret) => {
      if (err) {
        return callback(err)
      }
      // Set the generated secret for one call and then discard it
      oauth2._clientSecret = clientSecret
      originalGetOAuthAccessToken.call(oauth2, code, params, callback)
      oauth2._clientSecret = null
    })
  }
}

/**
 * @param {StrategyOptions} options
 * @returns {StrategyOptions}
 */
AppleSignInStrategy.normalizeOptions = function (options) {
  const normalized = { ...options } // Clone options since we are modifying it
  normalized.authorizationURL = options.authorizationURL || AUTHORIZATION_URL
  normalized.tokenURL = options.tokenURL || TOKEN_URL
  normalized.skipUserProfile = true // There is no user profile for Apple ID...
  normalized.passReqToCallback = true // ...User details will be in the request
  return normalized
}

/**
 * @param {StrategyOptions} originalOptions
 * @param {function|void} originalVerify
 */
AppleSignInStrategy.normalizeVerify = function (originalOptions, originalVerify) {
  const getUserProfileVerify = AppleSignInStrategy.createVerifyCallback(originalOptions)
  if (typeof originalVerify !== 'function') {
    return getUserProfileVerify
  }
  const arity = originalVerify.length
  if (!(artity >= 4 && arity <= 6)) {
    throw new Error('AppleSignInStrategy verify callback must take between 4 and 6 arguments')
  }
  return function (req, accessToken, refreshToken, params, profile, done) {
    const wrappedDone = function (err, profile, challenge, status) {
      if (err) {
        return done(err)
      }
      if (!profile) {
        return done(null, false, challenge, status)
      }
      if (arity === 6) {
        return originalVerify(req, accessToken, refreshToken, params, profile, done)
      }
      if (arity === 5 && originalOptions.passReqToCallback) {
        return originalVerify(req, accessToken, refreshToken, profile, done)
      }
      if (arity === 5) {
        return originalVerify(accessToken, refreshToken, params, profile, done)
      }
      if (arity === 4) {
        return originalVerify(accessToken, refreshToken, profile, done)
      }
    }
    getUserProfileVerify(req, accessToken, refreshToken, params, profile, wrappedDone)
  }
}

/**
 * @param {StrategyOptions} options
 * @returns {function}
 */
AppleSignInStrategy.createVerifyCallback = function (options) {
  const validateIdentityToken = createIdentityTokenValidator(options)
  return function (req, accessToken, refreshToken, params, profile, done) {
    validateIdentityToken(params['id_token'], (err, identityPayload) => {
      if (err) {
        const message = 'response `id_token` is invalid: ' + err.message
        return done(null, false, { message })
      }
      done(null, AppleSignInStrategy.createUserProfile(req, identityPayload))
    })
  }
}

/**
 * Create a user profile from the authorization redirect and the decoded identity token
 * @see https://developer.apple.com/documentation/signinwithapplejs/incorporating_sign_in_with_apple_into_other_platforms#3332115
 * @see https://developer.apple.com/documentation/signinwithapplerestapi/authenticating_users_with_sign_in_with_apple#3383773
 */
AppleSignInStrategy.createUserProfile = function (req, identityPayload) {
  const { email, sub: userIdentifier } = identityPayload
  let firstName
  let lastName
  let displayName
  if (req.body && req.body.user) {
    const { name } = JSON.parse(req.body.user)
    if (name) {
      firstName = name.firstName
      lastName = name.lastName
      displayName = [ firstName, lastName ].filter(Boolean).join(' ')
    }
  }
  return {
    provider: 'apple',
    'provider_id': userIdentifier,
    id: userIdentifier,
    email: email,
    emails: [
      { value: email }
    ],
    displayName: displayName || '',
    name: {
      familyName: lastName || '',
      givenName: firstName || '',
      middleName: ''
    }
  }
}

module.exports = AppleSignInStrategy
