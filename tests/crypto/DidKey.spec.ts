import DidKey from '../../lib/crypto/DidKey';
import { KeyType } from '../../lib/crypto/KeyType';
import { KeyUse } from '../../lib/crypto/KeyUse';
import KeyObject from '../../lib/crypto/KeyObject';
import WebCrypto from 'node-webcrypto-ossl';
import base64url from 'base64url';
import { KeyExport } from '../../lib/crypto/KeyExport';

class CryptoObject {
  /** Name of the crypto object */
  public name: string = '';

  /** Crypto object  */
  public crypto: any = null;
}

const webCryptoClass = new WebCrypto();

const crytoObjects: CryptoObject[] = [ { name: 'node-webcrypto-ossl', crypto: webCryptoClass } ];

describe('DidKey', () => {
  describe('Test constructor oct key', () => {
    it('Should set the right properties including symmetric key.', (done) => {
      let sampleKey = '1234567890123456';
      crytoObjects.forEach(async (cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: 'SHA-256' };
        let didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);
        expect(KeyType.Oct).toEqual(didKey.keyType);
        expect(KeyUse.Signature).toEqual(didKey.keyUse);
        expect(alg).toEqual(didKey.algorithm);
        expect(true).toEqual(didKey.exportable);

        let key: any = await didKey.getJwkKey(KeyExport.Secret);
        expect(key).not.toBeNull();
        expect(key.kty).toBe('oct');
        expect(base64url.encode(Buffer.from(sampleKey))).toBe(key.k);
      });
      done();
    });

    it('generate symmetric key.', (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: 'SHA-256' };
        let didKey = new DidKey(cryptoObj.crypto, alg, null, true);
        expect(KeyType.Oct).toEqual(didKey.keyType);
        expect(KeyUse.Signature).toEqual(didKey.keyUse);
        expect(alg).toEqual(didKey.algorithm);
        expect(true).toEqual(didKey.exportable);

        let key = await didKey.getJwkKey(KeyExport.Secret);
        expect(key).not.toBeNull();
        expect(key.kty).toBe('oct');
        expect(key.k).not.toBeNull();
        expect(key.k).not.toBeUndefined();
      });
      done();
    });

    it('Check throws.', async (done) => {

      try {
        let didKey = new DidKey(webCryptoClass, { name: 'xxx' }, null);
        expect(didKey).toBeUndefined();
        fail('should throw exception');
      } catch (err) {
        expect(`The algorithm 'xxx' is not supported`).toBe(err.message);
      }

      try {
        let didKey = new DidKey(webCryptoClass, { }, null, true);
        await didKey.getJwkKey(KeyExport.Secret);
        fail('should throw exception');
      } catch (err) {
        expect('Missing property name in algorithm').toBe(err.message);
      }

      try {
        const alg = { name: 'hmac', hash: 'SHA-256' };
        let didKey = new DidKey(webCryptoClass, alg, undefined, true);
        await didKey.getJwkKey(KeyExport.Secret);
        fail('should throw exception');
      } catch (err) {
        expect('Key must be defined').toBe(err.message);
      }

      try {
        const alg = { name: 'hmac', hash: 'SHA-256' };
        let didKey = new DidKey(webCryptoClass, alg, null, true);
        let did: any = didKey as any;
        did._keyType = 10;

        await didKey.getJwkKey(KeyExport.Secret);
        fail('should throw exception');
      } catch (err) {
        expect(`Key type '10' not supported`).toBe(err.message);
      }

      // test getJwkKeyFromKeyObject exceptions
      let alg = { name: 'hmac', hash: 'SHA-256' };
      let didKey = new DidKey(webCryptoClass, alg, null, true);
      let did: any = didKey as any;
      did.getJwkKeyFromKeyObject(KeyExport.Secret, null).catch((err: any) => {
        expect(`keyObject argument in getJwkKey cannot be null`).toBe(err.message);
      });

      did._keyType = 10;
      did.getJwkKeyFromKeyObject(KeyExport.Secret, 1).catch((err: any) => {
        expect(`DidKey:getJwkKey->10 is not supported`).toBe(err.message);
      });

      try {
        didKey = new DidKey(webCryptoClass, alg, null, true);
        let did: any = didKey as any;
        did._keyUse = 10;
        did.setKeyUsage();
      } catch (err) {
        expect(`The value for KeyUse '10' is invalid. Needs to be sig or enc`).toBe(err.message);
      }

      done();
    });

  });

  describe('Test signing with oct key', () => {
    it('HMAC-SHA256.', async (done) => {
      let sampleKey = '1234567890';
      crytoObjects.forEach(async (cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: { name: 'SHA-256' } };
        let didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);

        const data = 'abcdefghij';

        // Make sure the key is set (promise is completed)
        let signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
        let correct: boolean = await didKey.verify(Buffer.from(data), signature);
        expect(true).toBe(correct);
      });
      done();
    });

    it('HMAC-SHA512.', async (done) => {
      let sampleKey = '1234567890';
      crytoObjects.forEach(async (cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: { name: 'SHA-512' } };
        let didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);

        const data = 'abcdefghij';
        await didKey.getJwkKey(KeyExport.Secret);
        let signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
        let correct: boolean = await didKey.verify(Buffer.from(data), signature);
        expect(true).toBe(correct);
      });
      done();
    });
  });

  describe('ECDSA', () => {
    it('secp256k1 sign and verify.', async (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
        let didKey = new DidKey(cryptoObj.crypto, alg, null, true);

        const data = 'abcdefghij';
        let signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
        let correct: boolean = await didKey.verify(Buffer.from(data), signature);
        expect(true).toBe(correct);
      });
      done();
    });

    describe('ECDSA', () => {
      it('secp256k1 sign and verify with imported key.', async (done) => {
        crytoObjects.forEach(async (cryptoObj) => {
          console.log(`Crypto object: ${cryptoObj.name}`);
          const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
          let generatedDidKey = new DidKey(cryptoObj.crypto, alg, null, true);
          let jwk = await generatedDidKey.getJwkKey(KeyExport.Private);
          let didKey = new DidKey(cryptoObj.crypto, alg, jwk, true);

          const data = 'abcdefghij';
          jwk = await didKey.getJwkKey(KeyExport.Private);
          expect(KeyType.EC).toBe(jwk.kty);
          let signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
                // Make sure there is only the public key
          jwk.d = undefined;
          didKey = new DidKey(cryptoObj.crypto, alg, jwk, true);
          await didKey.getJwkKey(KeyExport.Public);
          let correct: boolean = await didKey.verify(Buffer.from(data), signature);
          expect(true).toBe(correct);
        });
        done();
      });

      it('secp256k1 import.', async (done) => {
        crytoObjects.forEach(async (cryptoObj) => {
          console.log(`Crypto object: ${cryptoObj.name}`);
          const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };

          // Generate the key pair
          let didKey = new DidKey(cryptoObj.crypto, alg, null, true);

          let ecKey1 = await didKey.getJwkKey(KeyExport.Private);
          expect(ecKey1).not.toBeNull();
          expect('K-256').toBe(ecKey1.crv);
          expect('EC').toBe(ecKey1.kty);
        });
        done();
      });

    });

    describe('ECDH', () => {

      it('secp256k1 encrypt and decrypt.', async (done) => {
        crytoObjects.forEach(async (cryptoObj) => {
          console.log(`Crypto object: ${cryptoObj.name}`);

          console.log('Generate my key');
          let alg: any = { name: 'ECDH', namedCurve: 'P-256K' };
          let myDidKey = new DidKey(cryptoObj.crypto, alg, null, true);

          let myJwkEcKey = await myDidKey.getJwkKey(KeyExport.Private);
          let ecKey: any = await cryptoObj.crypto.subtle.importKey('jwk', myJwkEcKey, alg, true, [ 'deriveKey', 'deriveBits' ]);
          let privateEcKey = new KeyObject(KeyType.EC, ecKey);
          myJwkEcKey.d = undefined;
          ecKey = await cryptoObj.crypto.subtle.importKey('jwk', myJwkEcKey, alg, true, [ 'deriveKey', 'deriveBits' ]);
          alg.public = ecKey;
          let bits: any = await cryptoObj.crypto.subtle.deriveBits(alg, privateEcKey.privateKey, 128);
          expect(16).toBe(bits.byteLength);
        });
        done();
      });

    });
  });
});
