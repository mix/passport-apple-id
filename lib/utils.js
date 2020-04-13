// NPM imports
const jwt = require('jsonwebtoken')
const jwksClient = require('jwks-rsa')

const { JsonWebTokenError } = jwt

/** @typedef {(err: Error, signature: string) => void} ClientSecretGeneratorCallback */
/** @typedef {(done: ClientSecretGeneratorCallback) => void} ClientSecretGenerator */
/** @typedef {(err: Error, payload: object) => void} IdentityTokenValidatorCallback */
/** @typedef {(identityToken: string, done: IdentityTokenValidatorCallback) => void} IdentityTokenValidator */

const BASE_DOMAIN = 'https://appleid.apple.com'
const AUTHORIZATION_URL = BASE_DOMAIN + '/auth/authorize'
const TOKEN_URL = BASE_DOMAIN + '/auth/token'
const PUBLIC_KEYS_URL = BASE_DOMAIN + '/auth/keys'

/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) with the P-256 curve and the SHA-256 hash algorithm.
 *
 * @see https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens#3262048
 */
const KEY_SIGN_ALGORITHM = 'ES256'

/**
 * JWK only supports RS256 for asymmetric signatures
 * @see https://auth0.com/docs/tokens/concepts/jwks
 * @see https://developer.apple.com/documentation/signinwithapplerestapi/jwkset/keys
 */
const KEY_VERIFY_ALGORITHM = 'RS256'

/**
 * 6 months in seconds, which is the maximum supported value
 * @see https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens#3262048
 */
const MAX_TOKEN_DURATION = 15777000

const publicKeyStore = jwksClient({ jwksUri: PUBLIC_KEYS_URL })

/**
 * @param {object} options
 * @param {string} options.clientID
 * @param {string} options.keyID
 * @param {string} options.privateKey
 * @param {string} options.teamID
 * @returns {ClientSecretGenerator}
 * @see https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens
 */
function createClientSecretGenerator({ clientID, keyID, privateKey, teamID }) {
  const jwtOptions = { algorithm: KEY_SIGN_ALGORITHM, keyid: keyID }
  return function (done) {
    const claims = {
      aud: BASE_DOMAIN,
      exp: Math.floor((Date.now() + MAX_TOKEN_DURATION) / 1000),
      iat: Math.floor(Date.now() / 1000),
      iss: teamID,
      sub: clientID
    }
    jwt.sign(claims, privateKey, jwtOptions, done)
  }
}

/**
 * @param {object} options
 * @param {string} options.clientID
 * @returns {IdentityTokenValidator}
 * @see https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens
 */
function createIdentityTokenValidator({ clientID }) {
  const verifyOptions = {
    audience: clientID,
    issuer: BASE_DOMAIN,
    maxAge: MAX_TOKEN_DURATION
  }
  return function (identityToken, done) {
    let decoded
    try {
      decoded = jwt.decode(identityToken, { complete: true })
    } catch (err) {
      return done(err)
    }
    if (!decoded || !decoded.header) {
      return done(new JsonWebTokenError('invalid jwt token'))
    }
    const { alg, kid } = decoded.header
    if (alg !== KEY_VERIFY_ALGORITHM) {
      return done(new JsonWebTokenError('jwt algorithm cannot be verified: ' + alg))
    }
    if (!kid) {
      return done(new JsonWebTokenError('jwt header does not have a key id'))
    }
    publicKeyStore.getSigningKey(kid, (err, signingKey) => {
      if (err) {
        return done(err)
      }
      const publicKey = signingKey.getPublicKey()
      jwt.verify(identityToken, publicKey, verifyOptions, done)
    })
  }
}

module.exports = {
  AUTHORIZATION_URL,
  TOKEN_URL,
  createClientSecretGenerator,
  createIdentityTokenValidator
}
