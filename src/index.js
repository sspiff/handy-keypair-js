
/**
 * `@sspiff/handy-keypair` facilitates the use of rotatable, cloud-stored
 * key pairs with JSON web tokens in a cloud environment.
 *
 * Cloud providers often offer secure storage of "secrets" such as access
 * keys and login credentials, and some, such as AWS Secrets Manager,
 * can rotate keys on a schedule.  While convenient, this presents some
 * challenges for consumers of these secrets.
 *
 * First, the APIs for fetching the secrets usually introduce unacceptable
 * latency, so consumers look to cache them.  Second, key rotation requires
 * cached secrets to be periodically refreshed, and, in the case of
 * asymmetric key pairs, using a public key for signature verification
 * requires knowledge of the key pair version in use.
 *
 * `@sspiff/handy-keypair` attempts to address these challenges.  When a
 * key pair is created, it is given an expiration date that is based
 * on the expected rotation schedule.  Key material is cached after fetching,
 * and the cache is refreshed based on the expiration dates.
 * When signing JSON web tokens, the key name and version are
 * embedded in the token so that the corresponding public key can be used
 * for verification.  Additionally, the public key can be stored separate
 * from the private key.
 *
 * @module @sspiff/handy-keypair
 */

export {default as createKeyPair} from './createKeyPair'
export {default as jwtSign} from './jwtSign'
export {default as jwtVerify} from './jwtVerify'
export {default as publicKeyFromKeyPair} from './publicKeyFromKeyPair'
export {default as KeyPairCache} from './KeyPairCache'
export {default as PublicKeyCache} from './PublicKeyCache'

