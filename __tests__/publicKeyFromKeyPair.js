
const crypto = require('crypto')
import createKeyPair from '../src/createKeyPair'
import publicKeyFromKeyPair from '../src/publicKeyFromKeyPair'

jest.mock('crypto')
crypto.generateKeyPairSync.mockImplementation(() => ({
  privateKey: 'TEST_PRIVATEKEY_VALUE',
  publicKey: 'TEST_PUBLICKEY_VALUE'
}))

beforeEach(() => {
  jest.clearAllMocks()
})

describe('publicKeyFromKeyPair', () => {

  test('is a function', () => {
    expect(typeof publicKeyFromKeyPair).toBe('function')
  })

  test('returns a public key structure based on key pair', () => {
    const kp = createKeyPair({
      type: 'ec',
      options: { namedCurve: 'prime256v1' },
      name: 'TEST_KEYPAIR',
      version: 'TEST_VERSION',
      expiresAt: 12345
    })
    const pk = publicKeyFromKeyPair(kp)
    expect(pk.privateKey).toBe(undefined)
    expect(pk.publicKey).toBe('TEST_PUBLICKEY_VALUE')
    expect(pk.name).toBe('TEST_KEYPAIR')
    expect(pk.version).toBe('TEST_VERSION')
    expect(pk.expiresAt).toBe(12345 + (1 * 24 * 60 * 60))
  })

  test('sets expiresAt based on graceDays', () => {
    const kp = createKeyPair({
      type: 'ec',
      options: { namedCurve: 'prime256v1' },
      name: 'TEST_KEYPAIR',
      version: 'TEST_VERSION',
      expiresAt: 12345,
      graceDays: 5
    })
    const pk = publicKeyFromKeyPair(kp)
    expect(pk.expiresAt).toBe(12345 + (5 * 24 * 60 * 60))
  })

})

