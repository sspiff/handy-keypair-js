
import * as keypair from '../'

import createKeyPair from '../src/createKeyPair'
import jwtSign from '../src/jwtSign'
import jwtVerify from '../src/jwtVerify'
import publicKeyFromKeyPair from '../src/publicKeyFromKeyPair'
import KeyPairCache from '../src/KeyPairCache'
import PublicKeyCache from '../src/PublicKeyCache'


describe('handy-keypair', () => {

  test('has createKeyPair', () => {
    expect(keypair.createKeyPair).toBe(createKeyPair)
  })
  test('has jwtSign', () => {
    expect(keypair.jwtSign).toBe(jwtSign)
  })
  test('has jwtVerify', () => {
    expect(keypair.jwtVerify).toBe(jwtVerify)
  })
  test('has publicKeyFromKeyPair', () => {
    expect(keypair.publicKeyFromKeyPair).toBe(publicKeyFromKeyPair)
  })
  test('has KeyPairCache', () => {
    expect(keypair.KeyPairCache).toBe(KeyPairCache)
  })
  test('has PublicKeyCache', () => {
    expect(keypair.PublicKeyCache).toBe(PublicKeyCache)
  })

})

