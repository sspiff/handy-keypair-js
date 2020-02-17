
import {pipe, lruMemoize, perishableRetryPromise} from '@sspiff/handy'


/**
 * Creates a new public key cache.
 *
 * The cache facilitates the use of rotatable, cloud-stored key pairs by
 * caching keys fetched from high-latency cloud APIs and intelligently
 * retrying on transient failures.  When used with cloud functions, the
 * cache can be created at the module's top level to leverage it across
 * invocations of warm function instances.
 *
 * While the public key cache can be used directly, it is usually bound to
 * and used by {@link module:@sspiff/handy-keypair.jwtVerify jwtVerify()}.
 *
 * The cache is agnostic towards key storage, and a function
 * `fetchPublicKeyData()` must be provided.  Given a `keyName` and a
 * `keyVersion`, `fetchPublicKeyData()` should return a `Promise` that
 * resolves to the corresponding public key data (as originally returned by
 * {@link module:@sspiff/handy-keypair.publicKeyFromKeyPair publicKeyFromKeyPair()}).
 *
 * If a cached key version has expired, the returned promise will be rejected
 * with `'ESTALE'`.  The cache does not attempt to re-fetch expired versions
 * because a version's expiration date does not change.
 *
 * `maxCacheEntries` controls the maximum size of the cache.  Once this limit
 * is reached, new cache entries replace least-recently-used entries.
 *
 * If the promise returned by `fetchKeyPairData()` is rejected (other than
 * for expiration), then the cache will retry the fetch after some delay.
 * The cache will continue to yield the rejected promise until the delay has
 * passed and the fetch is retried.  The retry behavior is intended to
 * gracefully handle occasional transient errors in key retrieval, as might
 * be encountered in a cloud environment.
 *
 * The `retryFirstDelay` and `retryMaxDelay` parameters control the retry
 * behavior for failed key fetches.  `retryFirstDelay` is used as the first
 * retry delay.  A backoff scheme is implemented by doubling the delay for
 * each subsequent consecutive fetch failure, up to a maximum delay of
 * `retryMaxDelay`.  The cache tracks retry delays for each key separately.
 *
 * @class PublicKeyCache
 * @memberof module:@sspiff/handy-keypair
 * @param {Object} params
 * @param {function} params.fetchPublicKeyData - A function that, given the
 *   name and version of a key pair, returns a `Promise` resolving to the
 *   pair's public key (as originally produced by
 *   {@link module:@sspiff/handy-keypair.publicKeyFromKeyPair publicKeyFromKeyPair()}).
 * @param {number} params.maxCacheEntries - Maximum number of public keys
 *   to cache.
 * @param {number} params.retryFirstDelay - Milliseconds of delay after first
 *   fetch failure.
 * @param {number} params.retryMaxDelay - Maximum milliseconds of delay after
 *   consecutive fetch failures.
 *
 * @example
 * <caption>Typical usage pattern:</caption>
 * import {PublicKeyCache, jwtVerify} from '@sspiff/handy-keypair'
 * const verify = jwtVerify.bind(new PublicKeyCache({
 *   fetchPublicKeyData: (keyName, keyVersion) => ...,
 *   maxCacheEntries: 2,
 *   retryFirstDelay: 500,
 *   retryMaxDelay: 120000
 * })
 *
 * verify(...).then(payload => ...)
 */
function PublicKeyCache({
  fetchPublicKeyData,
  maxCacheEntries,
  retryFirstDelay,
  retryMaxDelay
}) {
  /**
   * Returns a `Promise` from the cache that resolves to the key pair's
   * public key.
   *
   * If the named public key promise is present in the cache and not expired,
   * then the cached promise will be returned.  If the named public key is not
   * in the cache, then a fetch for the key will be initiated and a new
   * promise returned.
   *
   * The promise may be rejected if an error is encountered fetching the
   * public key.
   *
   * If the named key has expired, the promise will be rejected with
   * `'ESTALE'`.  This condition is permanent and should not be expected to
   * clear by retrying the fetch (a newer version of the key should be
   * requested instead).
   *
   * @method getPublicKey
   * @memberof module:@sspiff/handy-keypair.PublicKeyCache
   * @param {string} keyName - Name of the key to fetch
   * @param {string} keyVersion - Version of the named key to fetch
   */
  this.getPublicKey = pipe(
    lruMemoize(maxCacheEntries, (keyName, keyVersion) =>
      perishableRetryPromise(retryFirstDelay, retryMaxDelay,
        p => p.noRefresh ? Promise.reject('ESTALE') :
          fetchPublicKeyData(keyName, keyVersion).then(keyData => {
            p.expiresAt = keyData.expiresAt * 1000
            p.noRefresh = true
            return keyData
          })
      )
    ),
    p => p().then(keyData => keyData.publicKey)
  )
}

export default PublicKeyCache

