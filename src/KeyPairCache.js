
import {pipe, lruMemoize, perishableRetryPromise} from '@sspiff/handy'


/**
 * Creates a new key pair cache.
 *
 * The cache facilitates the use of rotatable, cloud-stored key pairs by
 * caching keys fetched from high-latency cloud APIs, re-fetching when
 * keys expire, and intelligently retrying on transient failures.
 * When used with cloud functions, the cache can be created at the module's
 * top level to leverage it across invocations of warm function instances.
 *
 * While the key pair cache can be used directly, it is usually bound to
 * and used by {@link module:@sspiff/handy-keypair.jwtSign jwtSign()}.
 *
 * The cache is agnostic towards key storage, and a function
 * `fetchKeyPairData()` must be provided.  Given a `keyName`,
 * `fetchKeyPairData()` should return a `Promise` that resolves to the
 * corresponding key pair data (as originally produced by
 * {@link module:@sspiff/handy-keypair.createKeyPair createKeyPair()}).
 *
 * If the named key is on a rotation schedule and multiple versions are
 * available, `fetchKeyPairData()` should yield the most recent version.
 * If a cached key has expired, the cache will re-fetch the key with the
 * expectation that the key's rotation process will have made a new
 * version available.
 *
 * `maxCacheEntries` controls the maximum size of the cache.  Once this
 * limit is reached, new cache entries replace least-recently-used entries.
 *
 * If the promise returned by `fetchKeyPairData()` is rejected, then the
 * cache will retry the fetch after some delay.  The cache will
 * continue to yield the rejected promise until the delay has passed and
 * the fetch is retried.  This retry behavior is intended to gracefully
 * handle occasional transient errors in key retrieval, as might be
 * encountered in a cloud environment.
 *
 * The `retryFirstDelay` and `retryMaxDelay` parameters control the retry
 * behavior for failed key fetches.  `retryFirstDelay` is used as the first
 * retry delay.  A backoff scheme is implemented by doubling the delay for
 * each subsequent consecutive fetch failure, up to a maximum delay of
 * `retryMaxDelay`.  Once a fetch succeeds, a future fetch error will start
 * retrying with `retryFirstDelay`.  The cache tracks retry delays for each
 * key separately.
 *
 * @class KeyPairCache
 * @memberof module:@sspiff/handy-keypair
 * @param {Object} params
 * @param {function} params.fetchKeyPairData - A function that, given the name
 *   of a key pair, returns a `Promise` that will resolve to the *latest
 *   version* of the named key pair (as originally produced by
 *   {@link module:@sspiff/handy-keypair.createKeyPair createKeyPair()}).
 * @param {number} params.maxCacheEntries - Maximum number of key pairs to
 *  cache.
 * @param {number} params.retryFirstDelay - Milliseconds of delay after first
 *   consecutive fetch failure.
 * @param {number} params.retryMaxDelay - Maximum milliseconds of delay after
 *   consecutive fetch failures.
 *
 * @example
 * <caption>Typical usage pattern:</caption>
 * import {KeyPairCache, jwtSign} from '@sspiff/handy-keypair'
 * const sign = jwtSign.bind(new KeyPairCache({
 *   fetchKeyPairData: keyName => ...,
 *   maxCacheEntries: 1,
 *   retryFirstDelay: 500,
 *   retryMaxDelay: 120000
 * }))
 *
 * sign(...).then(payload => ...)
 */
function KeyPairCache({
  fetchKeyPairData,
  maxCacheEntries,
  retryFirstDelay,
  retryMaxDelay
}) {
  /**
   * Returns a `Promise` from the cache that resolves to the the named key
   * pair.
   *
   * If the named key pair promise is present in the cache and not expired,
   * then the cached promise will be returned.  If the named key pair is
   * not in the cache, or is expired, then a fetch for the pair will be
   * initiated and a new promise returned.
   *
   * The returned promise (cached or new) will be rejected if an error is
   * encountered fetching the key pair.
   *
   * ***NOTE:** The resolved key pair data includes the private key.*
   *
   * @method getKeyPair
   * @memberof module:@sspiff/handy-keypair.KeyPairCache
   * @param {string} keyName - Name of key to fetch
   * @returns {Promise} - Resolving to the key pair data.
   */
  this.getKeyPair = pipe(
    lruMemoize(maxCacheEntries, keyName =>
      perishableRetryPromise(retryFirstDelay, retryMaxDelay,
        p => fetchKeyPairData(keyName).then(keyPair => {
          p.expiresAt = keyPair.expiresAt * 1000
          return keyPair
        })
      )
    ),
    p => p()
  )
}

export default KeyPairCache

