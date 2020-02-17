
import jwt from 'jsonwebtoken'
import {unsplitl} from '@sspiff/handy'


/**
 * Verifies a JSON web token signed using a handy key pair.
 * Uses `jsonwebtoken` to verify the token, fetching the key named
 * `keyName` from the bound
 * {@link module:@sspiff/handy-keypair.KeyPairCache PublicKeyCache}.
 *
 * Because the key material may have to be fetched from storage,
 * `jwtVerify()` returns a `Promise` that resolves to the decoded payload.
 * The promise will be rejected if: the cache is unable to fetch the key,
 * the key has expired, or if verification otherwise fails.
 *
 * The given token should be one created using
 * {@link module:@sspiff/handy-keypair.jwtSign jwtSign()} as `jwtVerify()`
 * will use the token's embedded `kid` (supplied by `jwtSign()`) to identify
 * the specific key and key version.  The promise will be rejected with
 * `'EINVAL'` if the key name claimed by the token does not match the given
 * `keyName`.
 *
 * @function jwtVerify
 * @memberof module:@sspiff/handy-keypair
 * @param {string} token - The token passed to `jsonwebtoken.verify()`
 * @param {string} keyName - The name of the key to request from the bound
 *   `PublicKeyCache`
 * @param {Object} [options={}] - Additional options passed to
 *   `jsonwebtoken.verify()`
 * @returns {Promise} Resolves to the decoded payload
 *
 * @example
 * <caption>Typical usage pattern:</caption>
 * import {PublicKeyCache, jwtVerify} from '@sspiff/handy-keypair'
 * const verify = jwtVerify.bind(new PublicKeyCache({...})
 *
 * verify(token, 'myTokenSigningKey', {...}).then(payload => ...)
 */
function jwtVerify(token, keyName, options) {
  // first decode the token to get the declared key name and key version
  const {header} = jwt.decode(token, {complete: true})
  const [declaredKeyName, keyVersion] = unsplitl(header.kid.split('/'), '/', 1)
  if (declaredKeyName !== keyName)
    return Promise.reject('EINVAL')
  return this.getPublicKey(keyName, keyVersion).then(publicKey =>
    jwt.verify(token, publicKey, options))
}

export default jwtVerify

