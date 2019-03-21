import KeyObject from '../../lib/crypto/KeyObject';
import { KeyType } from '../../lib/crypto/KeyType';
import WebCrypto from 'node-webcrypto-ossl';

const crypto = new WebCrypto();

describe('Constructor', () => {
  describe('Test constructor', () => {
    it('Throw exception.', () => {
      try {
        let key = new KeyObject(KeyType.RSA, {});
        expect(key).toBeUndefined();
      } catch (err) {
        expect(err).toEqual(jasmine.any(Error));
        expect(`Key with type 'RSA' is expected to have the type public or private`).toBe(err.message);
      }
    });

    it('Should set the right properties for the symmetric key.', async (done) => {
      const alg = { name: 'hmac', hash: 'SHA-256' };
      let key = await (crypto.subtle.generateKey(alg, true, [ 'sign' ]) as Promise<any>);
      let keyObject: KeyObject = new KeyObject(KeyType.Oct, key);
      expect(KeyType.Oct).toBe(keyObject.keyType);
      expect(false).toBe(keyObject.isKeyPair);
      expect(false).toBe(keyObject.isPrivateKey);
      expect(false).toBe(keyObject.isPublicKeyCrypto);
      done();
    });

    it('Should set the right properties for the EC key.', async (done) => {
      let alg: any = { name: 'ECDH', namedCurve: 'K-256' };
      let key = await (crypto.subtle.generateKey(alg, true, [ 'deriveBits' ]) as Promise<any>);
      let keyObject: KeyObject = new KeyObject(KeyType.EC, key);
      expect(KeyType.EC).toBe(keyObject.keyType);
      expect(true).toBe(keyObject.isKeyPair);
      expect(true).toBe(keyObject.isPrivateKey);
      expect(true).toBe(keyObject.isPublicKeyCrypto);
      done();
    });

    it('Should set the right properties for the imported private key.', async (done) => {
      let alg: any = { name: 'ECDH', namedCurve: 'K-256' };
      let key: any = await (crypto.subtle.generateKey(alg, true, [ 'deriveBits' ]) as Promise<any>);
      let jwkKey: any = await (crypto.subtle.exportKey('jwk', key.privateKey) as Promise<any>);
      key = await (crypto.subtle.importKey('jwk', jwkKey, alg, true, [ 'deriveBits' ]) as Promise<any>);
      let keyObject: KeyObject = new KeyObject(KeyType.EC, key);
      expect(KeyType.EC).toBe(keyObject.keyType);
      expect(false).toBe(keyObject.isKeyPair);
      expect(true).toBe(keyObject.isPrivateKey);
      expect(true).toBe(keyObject.isPublicKeyCrypto);
      done();
    });

    it('Should set the right properties for the imported public key.', async (done) => {
      let alg: any = { name: 'ECDH', namedCurve: 'K-256' };
      let key: any = await (crypto.subtle.generateKey(alg, true, [ 'deriveBits' ]) as Promise<any>);
      let jwkKey: any = await (crypto.subtle.exportKey('jwk', key.publicKey) as Promise<any>);
      key = await (crypto.subtle.importKey('jwk', jwkKey, alg, true, [ 'deriveBits' ]) as Promise<any>);
      let keyObject: KeyObject = new KeyObject(KeyType.EC, key);
      expect(KeyType.EC).toBe(keyObject.keyType);
      expect(false).toBe(keyObject.isKeyPair);
      expect(false).toBe(keyObject.isPrivateKey);
      expect(true).toBe(keyObject.isPublicKeyCrypto);
      done();
    });
  });
});
