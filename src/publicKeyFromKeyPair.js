
/**
 * Returns the corresponding public key-only data for the given the key pair.
 *
 * `keyPair` should be a key pair data `Object` produced by
 * {@link module:@sspiff/handy-keypair.createKeyPair createKeyPair()}.
 *
 * `publicKeyFromKeyPair()` returns a JSON-serializable `Object`
 * representation of the public key.  This object is suitable for use with
 * {@link module:@sspiff/handy-keypair.PublicKeyCache PublicKeyCache}.
 *
 * @function publicKeyFromKeyPair
 * @memberof module:@sspiff/handy-keypair
 * @param {Object} keyPair - The key pair for which to produce public key data.
 * @returns {Object}
 */
function publicKeyFromKeyPair(keyPair) {
  return {
    name: keyPair.name,
    version: keyPair.version,
    publicKey: keyPair.publicKey,
    expiresAt: keyPair.expiresAt + (keyPair.graceDays * 24 * 60 * 60)
  }
}

export default publicKeyFromKeyPair

