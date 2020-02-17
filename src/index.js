
/**
 * `@sspiff/handy-keypair` facilitates the use of rotatable, cloud-stored
 * key pairs in a cloud environment.
 *
 * When a key pair is created, it is given an expiration date that is based
 * on the expected rotation schedule.
 *
 * @module @sspiff/handy-keypair
 */

export {default as createKeyPair} from './createKeyPair'
export {default as jwtSign} from './jwtSign'
export {default as jwtVerify} from './jwtVerify'
export {default as publicKeyFromKeyPair} from './publicKeyFromKeyPair'
export {default as KeyPairCache} from './KeyPairCache'
export {default as PublicKeyCache} from './PublicKeyCache'

