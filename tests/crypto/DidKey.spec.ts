import DidKey from '../../lib/crypto/DidKey';
import { KeyType } from '../../lib/crypto/KeyType';
import { KeyUse } from '../../lib/crypto/KeyUse';
import KeyObject from '../../lib/crypto/KeyObject';
import WebCrypto from 'node-webcrypto-ossl';
import base64url from 'base64url';

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
      crytoObjects.forEach((cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: 'SHA-256' };
        let didKey = new DidKey(cryptoObj.crypto, alg, KeyType.Oct, KeyUse.Signature, Buffer.from(sampleKey), true);
        expect(KeyType.Oct).toEqual(didKey.keyType);
        expect(KeyUse.Signature).toEqual(didKey.keyUse);
        expect(alg).toEqual(didKey.algorithm);
        expect(true).toEqual(didKey.exportable);

        didKey.jwkKey.then((key) => {
          expect(key).not.toBeNull();
          expect(key.kty).toBe('oct');
          expect(base64url.encode(Buffer.from(sampleKey))).toBe(key.k);
          done();
        });
      });
    });

    it('generate symmetric key.', (done) => {
      crytoObjects.forEach((cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: 'SHA-256' };
        let didKey = new DidKey(cryptoObj.crypto, alg, KeyType.Oct, KeyUse.Signature, null, true);
        expect(KeyType.Oct).toEqual(didKey.keyType);
        expect(KeyUse.Signature).toEqual(didKey.keyUse);
        expect(alg).toEqual(didKey.algorithm);
        expect(true).toEqual(didKey.exportable);

        didKey.jwkKey.then((key) => {
          expect(key).not.toBeNull();
          expect(key.kty).toBe('oct');
          expect(key.k).not.toBeNull();
          expect(key.k).not.toBeUndefined();
          done();
        });
      });
    });

    /*
     it('Check throws.', (done) => {
      // expect(new DidKey(webCryptoClass, { name: 'xxx' }, KeyType.Oct, KeyUse.Encryption, null, true)).toThrowError();
      let didKey = new DidKey(webCryptoClass, { name: 'xxx' }, KeyType.Oct, KeyUse.Encryption, null, true);
      expect(() => didKey.jwkKey.then()).toThrowError();

      done();
     });
     */
  });

  describe('Test signing with oct key', () => {
    it('HMAC-SHA256.', (done) => {
      let sampleKey = '1234567890';
      crytoObjects.forEach((cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: { name: 'SHA-256' } };
        let didKey = new DidKey(cryptoObj.crypto, alg, KeyType.Oct, KeyUse.Signature, Buffer.from(sampleKey), true);

        const data = 'abcdefghij';

        // Make sure the key is set (promise is completed)
        didKey.jwkKey.then(() => {
          didKey.sign(Buffer.from(data)).then((signature: ArrayBuffer) => {
            didKey.verify(Buffer.from(data), signature).then((correct: boolean) => {
              expect(true).toBe(correct);
              done();
            });
          });
        });
      });
    });

    it('HMAC-SHA512.', (done) => {
      let sampleKey = '1234567890';
      crytoObjects.forEach((cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: { name: 'SHA-512' } };
        let didKey = new DidKey(cryptoObj.crypto, alg, KeyType.Oct, KeyUse.Signature, Buffer.from(sampleKey), true);

        const data = 'abcdefghij';
        didKey.jwkKey.then(() => {
          didKey.sign(Buffer.from(data)).then((signature: ArrayBuffer) => {
            didKey.verify(Buffer.from(data), signature).then((correct: boolean) => {
              expect(true).toBe(correct);
              done();
            });
          });
        });
      });
    });
  });

  describe('ECDSA', () => {
    it('secp256k1 sign and verify.', (done) => {
      crytoObjects.forEach((cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };
        let didKey = new DidKey(cryptoObj.crypto, alg, KeyType.EC, KeyUse.Signature, null, true);

        const data = 'abcdefghij';
        didKey.jwkKey.then(() => {
          didKey.sign(Buffer.from(data)).then((signature: ArrayBuffer) => {
            didKey.verify(Buffer.from(data), signature).then((correct: boolean) => {
              expect(true).toBe(correct);
              done();
            });
          });
        });
      });
    });

    describe('ECDSA', () => {
      it('secp256k1 sign and verify with imported key.', (done) => {
        crytoObjects.forEach((cryptoObj) => {
          console.log(`Crypto object: ${cryptoObj.name}`);
          const alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };
          let generatedDidKey = new DidKey(cryptoObj.crypto, alg, KeyType.EC, KeyUse.Signature, null, true);
          generatedDidKey.jwkKey.then((jwk) => {
            let didKey = new DidKey(cryptoObj.crypto, alg, KeyType.EC, KeyUse.Signature, jwk, true);

            const data = 'abcdefghij';
            didKey.jwkKey.then(() => {
              didKey.sign(Buffer.from(data)).then((signature: ArrayBuffer) => {
                // Make sure there is only the public key
                jwk.d = undefined;
                didKey = new DidKey(cryptoObj.crypto, alg, KeyType.EC, KeyUse.Signature, jwk, true);
                didKey.jwkKey.then(() => {
                  didKey.verify(Buffer.from(data), signature).then((correct: boolean) => {
                    expect(true).toBe(correct);
                    done();
                  });
                });
              });
            });
          });
        });
      });
    });

    it('secp256k1 import.', (done) => {
      crytoObjects.forEach((cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };

        // Generate the key pair
        let didKey = new DidKey(cryptoObj.crypto, alg, KeyType.EC, KeyUse.Signature, null, true);

        didKey.jwkKey.then((ecKey1) => {
          expect(ecKey1).not.toBeNull();
          expect('K-256').toBe(ecKey1.crv);
          expect('EC').toBe(ecKey1.kty);
          done();
        });
      });
    });

    it('secp256k1 encrypt and decrypt.', (done) => {
      crytoObjects.forEach((cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);

        console.log('Generate my key');
        let alg: any = { name: 'ECDH', namedCurve: 'K-256' };
        let myDidKey = new DidKey(cryptoObj.crypto, alg, KeyType.EC, KeyUse.Encryption, null, true);

        myDidKey.jwkKey.then((myJwkEcKey) => {
          cryptoObj.crypto.subtle
            .importKey('jwk', myJwkEcKey, alg, true, [ 'deriveKey', 'deriveBits' ])
            .then((ecKey: any) => {
              let privateEcKey = new KeyObject(KeyType.EC, ecKey);
              myJwkEcKey.d = undefined;
              cryptoObj.crypto.subtle
                .importKey('jwk', myJwkEcKey, alg, true, [ 'deriveKey', 'deriveBits' ])
                .then((ecKey: any) => {
                  alg.public = ecKey;
                  cryptoObj.crypto.subtle.deriveBits(alg, privateEcKey.privateKey, 128).then((bits: any) => {
                    expect(16).toBe(bits.byteLength);
                    done();
                  });
                });
            });
        });
      });
    });
  });
});
