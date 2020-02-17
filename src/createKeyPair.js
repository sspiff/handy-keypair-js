
const crypto = require('crypto')

/**
 * Creates a new handy key pair.
 *
 * Uses node.js's `crypto.generateKeyPairSync()` to create a new key pair.
 * The `type` and `options` parameters are passed to `generateKeyPairSync()`,
 * except that `options.publicKeyEncoding` and `options.privateKeyEncoding`
 * are overridden by `createKeyPair()`.
 *
 * A handy key pair uses `name`, `version`, `expiresAt`, and `graceDays` to
 * support key identification, rotation, and expiration.
 *
 * `version` should uniquely distinguish the new key pair from other instances
 * of key pairs with the same `name`.  This facilitates key identification
 * when keys are periodically rotated.  `version` should be a string and
 * should not contain a `/` character.  Beyond these requirements,
 * `@sspiff/handy-keypair` treats the value as opaque.
 *
 * `expiresAt` defines the expiration date of the new key pair expressed as
 * the number of seconds since the epoch, and would typically be based on a
 * rotation schedule.  `graceDays` is the number of additional days beyond
 * `expiresAt` that public key should be considered valid.
 *
 * `createKeyPair()` returns a JSON-serializable `Object` representation of
 * the new key pair.  This `Object` is suitable for use with
 * {@link module:@sspiff/handy-keypair.publicKeyFromKeyPair publicKeyFromKeyPair()} and
 * {@link module:@sspiff/handy-keypair.KeyPairCache KeyPairCache}.
 *
 * ***NOTE:** The returned `Object` contains the private key material and
 * should be transmitted and stored securely.*
 *
 * When used with AWS Secrets Manager key rotation, the parameters
 * can be mapped as follows:
 *
 * | Parameter    | AWS Secrets Manager Usage                          |
 * | ------------ | -------------------------------------------------- |
 * | `name`       | Secrets Manager `SecretId`                         |
 * | `version`    | Rotation `clientRequestToken` or `SecretVersionId` |
 * | `expiresAt`  | Based on the current date and rotation schedule (`RotationRules.AutomaticallyAfterDays`) |
 * | Return value | Object which can be serialized to JSON for storage in Secrets Manager |
 *
 * @function createKeyPair
 * @memberof module:@sspiff/handy-keypair
 * @param {Object} params
 * @param {string} params.type - Type of key pair (`'rsa'`, `'ec'`, etc)
 * @param {Object} params.options - Additional options for
 *   `crypto.generateKeyPairSync()` specific to the key type
 * @param {string} params.name - Name of key
 * @param {string} params.version - Key version (for key rotation)
 * @param {number} params.expiresAt - Seconds since the epoch
 * @param {number} params.graceDays=1 - Additional days of public key validity
 *   beyond `expiresAt`
 * @returns {Object}
 *
 * @example
 * <caption>Create an elliptic curve key pair suitable for use with JSON web
 * tokens (ES256 algorithm):</caption>
 * import {createKeyPair} from '@sspiff/handy-keypair'
 *
 * keyPair = createKeyPair({
 *   type: 'ec',
 *   options: { namedCurve: 'prime256v1' },
 *   name: 'myKeyPair',
 *   version: '1',
 *   expiresAt: (Date.now() / 1000) + (180 * 24 * 60 * 60),  // 180 days
 * })
 */
function createKeyPair({
  type,
  options,
  name,
  version,
  expiresAt,
  graceDays=1
}) {
  // create a new key pair
  const {publicKey, privateKey} = crypto.generateKeyPairSync(type, {
    ...options,
    privateKeyEncoding: {'type': 'pkcs8', format: 'pem'},
    publicKeyEncoding: {'type': 'spki', format: 'pem'}
  })
  // wrap it in metadata
  return {
    name,
    version,
    privateKey,
    publicKey,
    expiresAt,
    graceDays
  }
}

export default createKeyPair

