import WebCrypto from 'node-webcrypto-ossl';
import KeyObject from '../../lib/crypto/KeyObject';
import { KeyType } from '../../lib/crypto/KeyType';

const crypto = new WebCrypto();

describe('KeyObject', () => {
  it('should throw on construction for invalid key', () => {
    expect(() => new KeyObject(KeyType.RSA, {})).toThrowError(`Key with type 'RSA' is expected to have the type public or private`);
  });

  it('should throw when determin', () => {
    expect(() => new KeyObject(KeyType.RSA, {})).toThrowError(`Key with type 'RSA' is expected to have the type public or private`);
  });

  it('should set the right properties for the symmetric key.', async (done) => {
    const alg = { name: 'hmac', hash: 'SHA-256' };
    const key = await (crypto.subtle.generateKey(alg, true, [ 'sign' ]) as Promise<any>);
    const keyObject: KeyObject = new KeyObject(KeyType.Oct, key);
    expect(keyObject.keyType).toEqual(KeyType.Oct);
    expect(keyObject.isKeyPair).toBeFalsy();
    expect(keyObject.isPrivateKey).toBeFalsy();
    expect(keyObject.isPublicKeyCrypto).toBeFalsy();
    done();
  });

  it('should set the right properties for the EC key.', async (done) => {
    const alg: any = { name: 'ECDH', namedCurve: 'K-256' };
    const key = await (crypto.subtle.generateKey(alg, true, [ 'deriveBits' ]) as Promise<any>);
    const keyObject: KeyObject = new KeyObject(KeyType.EC, key);
    expect(keyObject.keyType).toEqual(KeyType.EC);
    expect(keyObject.isKeyPair).toBeTruthy();
    expect(keyObject.isPrivateKey).toBeTruthy();
    expect(keyObject.isPublicKeyCrypto).toBeTruthy();
    done();
  });

  it('should set the right properties for the imported private key.', async (done) => {
    const alg: any = { name: 'ECDH', namedCurve: 'K-256' };
    let key: any = await (crypto.subtle.generateKey(alg, true, [ 'deriveBits' ]) as Promise<any>);
    const jwkKey: any = await (crypto.subtle.exportKey('jwk', key.privateKey) as Promise<any>);
    key = await (crypto.subtle.importKey('jwk', jwkKey, alg, true, [ 'deriveBits' ]) as Promise<any>);
    const keyObject: KeyObject = new KeyObject(KeyType.EC, key);
    expect(keyObject.keyType).toEqual(KeyType.EC);
    expect(keyObject.isKeyPair).toBeFalsy();
    expect(keyObject.isPrivateKey).toBeTruthy();
    expect(keyObject.isPublicKeyCrypto).toBeTruthy();
    done();
  });

  it('should set the right properties for the imported public key.', async (done) => {
    const alg: any = { name: 'ECDH', namedCurve: 'K-256' };
    let key: any = await (crypto.subtle.generateKey(alg, true, [ 'deriveBits' ]) as Promise<any>);
    const jwkKey: any = await (crypto.subtle.exportKey('jwk', key.publicKey) as Promise<any>);
    key = await (crypto.subtle.importKey('jwk', jwkKey, alg, true, [ 'deriveBits' ]) as Promise<any>);
    const keyObject: KeyObject = new KeyObject(KeyType.EC, key);
    expect(KeyType.EC).toBe(keyObject.keyType);
    expect(keyObject.isKeyPair).toBeFalsy();
    expect(keyObject.isPrivateKey).toBeFalsy();
    expect(keyObject.isPublicKeyCrypto).toBeTruthy();
    done();
  });
});
