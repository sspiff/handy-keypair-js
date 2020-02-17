
import {
  createKeyPair,
  jwtSign,
  jwtVerify,
  publicKeyFromKeyPair,
  KeyPairCache,
  PublicKeyCache
} from '../'


var TNOW = 0
var dateNowSpy = jest.spyOn(Date, 'now').mockImplementation(() => TNOW)

const KEYPAIRS = {}
const PUBLICKEYS = {}
function createTestKey({name, version, expiresAt}) {
  const keyPair = createKeyPair({
    type: 'ec',
    options: { namedCurve: 'prime256v1' },
    name,
    version,
    expiresAt
  })
  const publicKeyData = publicKeyFromKeyPair(keyPair)
  KEYPAIRS[name] = JSON.stringify(keyPair)
  PUBLICKEYS[`${name}/${version}`] = JSON.stringify(publicKeyData)
}
const fetchKeyPairData = jest.fn(keyName => {
  const kp = KEYPAIRS[keyName]
  if (kp)
    return Promise.resolve(JSON.parse(kp))
  else
    return Promise.reject('ENOENT')
})
const _sign = jwtSign.bind(new KeyPairCache({
    maxCacheEntries: 10,
    retryFirstDelay: 500,
    retryMaxDelay: 120000,
    fetchKeyPairData
  }))
const sign = (payload, keyName, options={}) =>
  _sign(payload, keyName, {algorithm: 'ES256', ...options})
const fetchPublicKeyData = jest.fn((keyName, keyVersion) => {
  const pk = PUBLICKEYS[`${keyName}/${keyVersion}`]
  if (pk)
    return Promise.resolve(JSON.parse(pk))
  else
    return Promise.reject('ENOENT')
})
const verify = jwtVerify.bind(new PublicKeyCache({
    maxCacheEntries: 20,
    retryFirstDelay: 500,
    retryMaxDelay: 120000,
    fetchPublicKeyData
  }))

beforeEach(() => {
  jest.clearAllMocks()
  TNOW = 0
})

describe('jwt', () => {

  test('jwtSign is a function', () => {
    expect(typeof jwtSign).toBe('function')
  })

  test('jwtVerify is a function', () => {
    expect(typeof jwtVerify).toBe('function')
  })

  test('sign and verify', async () => {
    createTestKey({name: 'testkey', version: '1', expiresAt: 100})
    const payload = {foo: 'foo', bar: 'bar'}
    const token = await sign(payload, 'testkey', {noTimestamp: true})
    const claims = await verify(token, 'testkey')
    expect(claims).toEqual(payload)
  })

  test('sign and verify with key rotation', async () => {
    const ONEDAY = 24 * 60 * 60
    createTestKey({name: 'rotate', version: '1', expiresAt: 1})
    const token1 = await sign({}, 'rotate')
    expect(fetchKeyPairData.mock.calls.length).toBe(1)
    // advance time to expire key pair version 1 (but not enough to
    // expire the corresponding public key)
    TNOW += 2000
    await expect(sign({}, 'rotate')).rejects.toBe('ESTALE')
    expect(fetchKeyPairData.mock.calls.length).toBe(2)
    // "rotate" the key
    createTestKey({name: 'rotate', version: '2', expiresAt: TNOW + ONEDAY})
    // this sign should still fail even though we've rotated due to
    // the retry delay
    await expect(sign({}, 'rotate')).rejects.toBe('ESTALE')
    // now advance time past the retry delay
    TNOW += 1000
    const token2 = await sign({}, 'rotate')
    expect(fetchKeyPairData.mock.calls.length).toBe(3)
    // both tokens should verify
    await expect(verify(token1, 'rotate')).resolves.toBeDefined()
    await expect(verify(token2, 'rotate')).resolves.toBeDefined()
    expect(fetchPublicKeyData.mock.calls.length).toBe(2)
    // now advance time to expire public key version 1
    TNOW += ONEDAY * 1000
    // token1 should reject, token2 should verify
    await expect(verify(token1, 'rotate')).rejects.toBe('ESTALE')
    await expect(verify(token2, 'rotate')).resolves.toBeDefined()
    expect(fetchPublicKeyData.mock.calls.length).toBe(2)
  })

  test('rejects on key mismatch', async () => {
    createTestKey({name: 'mismatch', version: '1', expiresAt: 100})
    const token = await sign({}, 'mismatch')
    await expect(verify(token, 'testkey')).rejects.toBe('EINVAL')
  })

  test('propagates verify errors', async () => {
    createTestKey({name: 'verifyerror', version: '1', expiresAt: 60 * 1000})
    const token = await sign({}, 'verifyerror', {expiresIn: 5})
    await expect(verify(token, 'verifyerror')).resolves.toBeDefined()
    TNOW += 10 * 1000
    await expect(verify(token, 'verifyerror')).rejects.toThrow('expired')
  })

})

