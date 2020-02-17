
const crypto = require('crypto')
import createKeyPair from '../src/createKeyPair'
import KeyPairCache from '../src/KeyPairCache'


jest.mock('crypto')
crypto.generateKeyPairSync.mockImplementation(() => ({
  privateKey: 'TEST_PRIVATEKEY_VALUE',
  publicKey: 'TEST_PUBLICKEY_VALUE'
}))

var TNOW = 0
var dateNowSpy = jest.spyOn(Date, 'now').mockImplementation(() => TNOW)

describe('KeyPairCache', () => {

  test('is a function', () => {
    expect(typeof KeyPairCache).toBe('function')
  })

  test('produces an object with getKeyPair', () => {
    const c = new KeyPairCache({
      fetchKeyPairData: keyName => Promise.resolve({}),
      maxCacheEntries: 1,
      retryFirstDelay: 500,
      retryMaxDelay: 120000
    })
    expect(typeof c.getKeyPair).toBe('function')
  })

  test('calls fetchKeyPairData', () => {
    const f = jest.fn(keyName => Promise.resolve({}))
    const c = new KeyPairCache({
      fetchKeyPairData: f,
      maxCacheEntries: 1,
      retryFirstDelay: 500,
      retryMaxDelay: 120000
    })
    c.getKeyPair('foo')
    expect(f.mock.calls.length).toBe(1)
    expect(f.mock.calls[0][0]).toBe('foo')
  })

  test('returns the key pair', async () => {
    const keyPair = createKeyPair({
      type: 'foo',
      options: {},
      name: 'testkey',
      version: '1',
      expiresAt: 100
    })
    const c = new KeyPairCache({
      maxCacheEntries: 1,
      retryFirstDelay: 500,
      retryMaxDelay: 120000,
      fetchKeyPairData: keyName => Promise.resolve(keyPair)
    })
    await expect(c.getKeyPair('testkey')).resolves.toBe(keyPair)
  })

  test('rejects already-expired keys', async () => {
    const c = new KeyPairCache({
      maxCacheEntries: 1,
      retryFirstDelay: 500,
      retryMaxDelay: 120000,
      fetchKeyPairData: keyName => Promise.resolve(
        createKeyPair({
          type: 'foo',
          options: {},
          name: 'testkey',
          version: '1',
          expiresAt: 0
        }))
    })
    TNOW = 100
    await expect(c.getKeyPair('testkey')).rejects.toBe('ESTALE')
  })

})

