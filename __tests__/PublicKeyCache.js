
const crypto = require('crypto')
import createKeyPair from '../src/createKeyPair'
import publicKeyFromKeyPair from '../src/publicKeyFromKeyPair'
import PublicKeyCache from '../src/PublicKeyCache'


jest.mock('crypto')
crypto.generateKeyPairSync.mockImplementation(() => ({
  privateKey: 'TEST_PRIVATEKEY_VALUE',
  publicKey: 'TEST_PUBLICKEY_VALUE'
}))

var TNOW = 0
var dateNowSpy = jest.spyOn(Date, 'now').mockImplementation(() => TNOW)

describe('PublicKeyCache', () => {

  test('is a function', () => {
    expect(typeof PublicKeyCache).toBe('function')
  })

  test('produces an object with getPublicKey', () => {
    const c = new PublicKeyCache({
      fetchPublicKeyData: (keyName, keyVersion) => Promise.resolve({}),
      maxCacheEntries: 1,
      retryFirstDelay: 500,
      retryMaxDelay: 120000
    })
    expect(typeof c.getPublicKey).toBe('function')
  })

  test('calls fetchPublicKeyData', () => {
    const f = jest.fn((keyName, keyVersion) => Promise.resolve({}))
    const c = new PublicKeyCache({
      fetchPublicKeyData: f,
      maxCacheEntries: 1,
      retryFirstDelay: 500,
      retryMaxDelay: 120000
    })
    c.getPublicKey('testkey', '1')
    expect(f.mock.calls.length).toBe(1)
    expect(f.mock.calls[0][0]).toBe('testkey')
    expect(f.mock.calls[0][1]).toBe('1')
  })

  test('returns the public key', async () => {
    const keyPair = createKeyPair({
      type: 'foo',
      options: {},
      name: 'testkey',
      version: '1',
      expiresAt: 100
    })
    const c = new PublicKeyCache({
      maxCacheEntries: 1,
      retryFirstDelay: 500,
      retryMaxDelay: 120000,
      fetchPublicKeyData: (keyName, keyVersion) => Promise.resolve(
        publicKeyFromKeyPair(keyPair))
    })
    await expect(c.getPublicKey('testkey', '1')).resolves
      .toBe(keyPair.publicKey)
  })

  test('rejects already-expired keys', async () => {
    const keyPair = createKeyPair({
      type: 'foo',
      options: {},
      name: 'testkey',
      version: '1',
      expiresAt: 0
    })
    const c = new PublicKeyCache({
      maxCacheEntries: 1,
      retryFirstDelay: 500,
      retryMaxDelay: 120000,
      fetchPublicKeyData: (keyName, keyVersion) => Promise.resolve(
        publicKeyFromKeyPair(keyPair))
    })
    TNOW = (100 + (1 * 24 * 60 * 60) * 1000)
    await expect(c.getPublicKey('testkey')).rejects.toBe('ESTALE')
  })

})

