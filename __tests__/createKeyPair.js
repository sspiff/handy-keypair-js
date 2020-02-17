
const crypto = require('crypto')
import createKeyPair from '../src/createKeyPair'

jest.mock('crypto')
crypto.generateKeyPairSync.mockImplementation(() => ({
  privateKey: 'TEST_PRIVATEKEY_VALUE',
  publicKey: 'TEST_PUBLICKEY_VALUE'
}))

beforeEach(() => {
  jest.clearAllMocks()
})

describe('createKeyPair', () => {

  test('is a function', () => {
    expect(typeof createKeyPair).toBe('function')
  })

  test('returns a key pair structure with caller\'s parameters', () => {
    const kp = createKeyPair({
      type: 'ec',
      options: { namedCurve: 'prime256v1' },
      name: 'TEST_KEYPAIR',
      version: 'TEST_VERSION',
      expiresAt: 12345
    })
    expect(kp.privateKey).toBe('TEST_PRIVATEKEY_VALUE')
    expect(kp.publicKey).toBe('TEST_PUBLICKEY_VALUE')
    expect(kp.name).toBe('TEST_KEYPAIR')
    expect(kp.version).toBe('TEST_VERSION')
    expect(kp.expiresAt).toBe(12345)
  })

  test('calls crypto.generateKeyPairSync with caller\'s options', () => {
    const type = 'ec'
    const options = { namedCurve: 'prime256v1', someOtherOption: 'foo' }
    const kp = createKeyPair({
      type,
      options,
      name: 'TEST_KEYPAIR',
      version: 'TEST_VERSION',
      expiresAt: 12345
    })
    const m = crypto.generateKeyPairSync.mock
    expect(m.calls.length).toBe(1)
    expect(m.calls[0][0]).toBe(type)
    Object.entries(options).forEach(([k, v]) => {
      expect(m.calls[0][1][k]).toBe(v)
    })
  })

})

