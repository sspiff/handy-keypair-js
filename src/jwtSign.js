
import jwt from 'jsonwebtoken'


/**
 * Signs a JSON web token using a handy key pair.
 * Uses `jsonwebtoken` to create and sign the token, fetching the key named
 * `keyName` from the bound
 * {@link module:@sspiff/handy-keypair.KeyPairCache KeyPairCache}.
 *
 * Because the key material may have to be fetched from storage, `jwtSign()`
 * returns a `Promise` that resolves to the signed JSON web token.
 * The promise will be rejected if: the cache is unable to fetch the key,
 * the key has expired, or if signing otherwise fails.
 *
 * Additionally, `jwtSign()`:
 *
 * - overrides `options.keyid` with a key identifier incorporating
 *   the key name and version.  This enables
 *   {@link module:@sspiff/handy-keypair.jwtVerify jwtVerify()} to select
 *   the appropriate key material during verification.
 * - does not attempt to map the expiration date of the handy
 *   key pair to the token's `exp` claim.  Instead, callers should specify
 *   this via `options.expiresIn` (or `payload.exp`) as described in the
 *   `jsonwebtoken` documentation.
 *
 * @function jwtSign
 * @memberof module:@sspiff/handy-keypair
 * @param {*} payload - The token payload passed to `jsonwebtoken.sign()`
 * @param {string} keyName - The name of the key to request from the bound
 *   `KeyPairCache`
 * @param {Object} [options={}] - Additional options passed to
 *   `jsonwebtoken.sign()`
 * @returns {Promise} Resolves to the signed JSON web token
 *
 * @example
 * <caption>Typical usage pattern:</caption>
 * import {KeyPairCache, jwtSign} from '@sspiff/handy-keypair'
 * const sign = jwtSign.bind(new KeyPairCache({...})
 *
 * sign(myTokenPayload, 'myTokenSigningKey', {...}).then(token => ...)
 */
function jwtSign(payload, keyName, options={}) {
  return this.getKeyPair(keyName).then(keyPair =>
    jwt.sign(
      payload,
      keyPair.privateKey,
      {
        ...options,
        keyid: `${keyPair.name}/${keyPair.version}`
      }
    )
  )
}

export default jwtSign

