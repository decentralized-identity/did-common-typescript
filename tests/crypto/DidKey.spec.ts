import base64url from 'base64url';
import WebCrypto from 'node-webcrypto-ossl';
import DidKey from '../../lib/crypto/DidKey';
import { KeyExport } from '../../lib/crypto/KeyExport';
import KeyObject from '../../lib/crypto/KeyObject';
import { KeyType } from '../../lib/crypto/KeyType';
import { KeyUse } from '../../lib/crypto/KeyUse';
import { KeyOperation } from '../../lib/crypto/KeyOperation';

class CryptoObject {
  /** Name of the crypto object */
  public name: string = '';

  /** Crypto object  */
  public crypto: any = null;
}

const webCryptoClass = new WebCrypto();

const crytoObjects: CryptoObject[] = [ { name: 'node-webcrypto-ossl', crypto: webCryptoClass } ];

const hmacAlgorithm = { name: 'hmac', hash: { name: 'SHA-256' } };
const sampleKey = '1234567890123456';

describe('DidKey', () => {

  let originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;

  beforeEach(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
  });

  afterEach(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
  });

  describe('constructed with an Octet key', () => {
    it('should set the right properties including symmetric key.', (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
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

    it('should generate a symmetric key.', (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
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

    it('should throw on unsupported algorithm ', () => {
      expect(() => new DidKey(webCryptoClass, { name: 'xxx' }, null)).toThrowError(`The algorithm 'xxx' is not supported`);
    });

    it('should throw on missing algorithm property', async (done) => {
      try {
        const didKey = new DidKey(webCryptoClass, { }, null, true);
        await didKey.getJwkKey(KeyExport.Secret);
        fail('Expected an exception');
      } catch (error) {
        expect(error.message).toBe('Missing property name in algorithm');
        done();
      }
    });

    it('should throw on missing key', async (done) => {
      try {
        const didKey = new DidKey(webCryptoClass, hmacAlgorithm, undefined, true);
        await didKey.getJwkKey(KeyExport.Secret);
        fail('Expected an exception');
      } catch (error) {
        expect(error.message).toBe('Key must be defined');
        done();
      }
    });

    it('should throw when key type not supported', async (done) => {
      try {
        const didKey = new DidKey(webCryptoClass, hmacAlgorithm, null, true);
        const did: any = didKey as any;
        did._keyType = 10;
        await didKey.getJwkKey(KeyExport.Secret);
        fail('Expected an exception');
      } catch (error) {
        expect(error.message).toBe(`Key type '10' not supported`);
        done();
      }
    });

    it('should throw when key object is null', async (done) => {
      try {
        const didKey = new DidKey(webCryptoClass, hmacAlgorithm, null, true);
        const did: any = didKey as any;
        await did.getJwkKeyFromKeyObject(KeyExport.Secret, null);
      } catch (error) {
        expect(error.message).toBe('keyObject argument in getJwkKey cannot be null');
        done();
      }
    });

    it('should throw when getJwkKey passed unsupported key type', async (done) => {
      try {
        const didKey = new DidKey(webCryptoClass, hmacAlgorithm, null, true);
        const did: any = didKey as any;
        did._keyType = 10;
        await did.getJwkKeyFromKeyObject(KeyExport.Secret, 1);
      } catch (error) {
        expect(error.message).toBe('DidKey:getJwkKey->10 is not supported');
        done();
      }
    });

    it('should create and verify a HMAC-SHA256 signature', async (done) => {
      let sampleKey = '1234567890';
      crytoObjects.forEach(async (cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: { name: 'SHA-256' } };
        const didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);

        const data = 'abcdefghij';

        // Make sure the key is set (promise is completed)
        const signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
        const correct: boolean = await didKey.verify(Buffer.from(data), signature);
        expect(correct).toBeTruthy();
      });
      done();
    });

    it('should create and verify a HMAC-SHA512 signature', async (done) => {
      let sampleKey = '1234567890';
      crytoObjects.forEach(async (cryptoObj) => {
        console.log(`Crypto object: ${cryptoObj.name}`);
        const alg = { name: 'hmac', hash: { name: 'SHA-512' } };
        const didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);

        const data = 'abcdefghij';
        await didKey.getJwkKey(KeyExport.Secret);
        const signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
        const correct: boolean = await didKey.verify(Buffer.from(data), signature);
        expect(correct).toBeTruthy();
      });
      done();
    });

    it('should return the correct key operations for a signature key', () => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'hmac', hash: 'SHA-256' };
        const didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);
        const operations: Array<KeyOperation> = didKey.getKeyOperations(KeyUse.Signature);
        expect(operations).toEqual([ KeyOperation.Sign, KeyOperation.Verify ]);
      });
    });

    it('should return the correct key operations for a encryption key', () => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'hmac', hash: 'SHA-256' };
        const didKey = new DidKey(cryptoObj.crypto, alg, Buffer.from(sampleKey), true);
        const operations: Array<KeyOperation> = didKey.getKeyOperations(KeyUse.Encryption);
        expect(operations).toEqual([ KeyOperation.Encrypt, KeyOperation.Decrypt ]);
      });
    });
  });

  describe('constructed with an ECDSA key', () => {
    it('should sign and verify using a secp256k1 key', async (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
        const didKey = new DidKey(cryptoObj.crypto, alg, null, true);

        const data = 'abcdefghij';
        const signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
        const correct: boolean = await didKey.verify(Buffer.from(data), signature);
        expect(correct).toBeTruthy();
      });
      done();
    });

    it('should throw when no private key', async (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
        const didKey = new DidKey(cryptoObj.crypto, alg, null, true);
        spyOn(didKey, 'getKeyObject').and.returnValue(undefined);
        const data = 'abcdefghij';
        try {
          await didKey.sign(Buffer.from(data));
        } catch (error) {
          expect(error.message).toEqual(`A private key with id of 'EC-sig-private' required to validate the signature cannot be found.`);
          done();
        }
      });
    });

    it('should sign and verify with an imported secp256k1 key.', async (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
        const generatedDidKey = new DidKey(cryptoObj.crypto, alg, null, true);
        let jwk = await generatedDidKey.getJwkKey(KeyExport.Private);
        let didKey = new DidKey(cryptoObj.crypto, alg, jwk, true);

        const data = 'abcdefghij';
        jwk = await didKey.getJwkKey(KeyExport.Private);
        expect(KeyType.EC).toBe(jwk.kty);
        const signature: ArrayBuffer = await didKey.sign(Buffer.from(data));

        // Make sure there is only the public key
        jwk.d = undefined;
        didKey = new DidKey(cryptoObj.crypto, alg, jwk, true);
        await didKey.getJwkKey(KeyExport.Public);
        const correct: boolean = await didKey.verify(Buffer.from(data), signature);
        expect(correct).toBeTruthy();
      });
      done();
    });

    it('should successfully import a secp256k1 key', async (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };

        // Generate the key pair
        const didKey = new DidKey(cryptoObj.crypto, alg, null, true);

        const ecKey1 = await didKey.getJwkKey(KeyExport.Private);
        expect(ecKey1).not.toBeNull();
        expect(ecKey1.crv).toBe('P-256K');
        expect(ecKey1.kty).toBe('EC');
      });
      done();
    });

    it('should return the correct key operations for a EC encryption key', () => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
        const didKey = new DidKey(cryptoObj.crypto, alg, null, true);
        const operations: Array<KeyOperation> = didKey.getKeyOperations(KeyUse.Encryption);
        expect(operations).toEqual([ KeyOperation.DeriveKey, KeyOperation.DeriveBits ]);
      });
    });
  });

  describe('constructed with an ECDH key', () => {
    it('should derive bits of for EC based Diffie-Hellman exchange', async (done) => {
      crytoObjects.forEach(async (cryptoObj) => {
        const alg: any = { name: 'ECDH', namedCurve: 'P-256K' };
        const normalizedAlgorithm = DidKey.normalizeAlgorithm(alg);
        const keyOperations = [ 'deriveKey', 'deriveBits' ];
        const privateKey = new DidKey(cryptoObj.crypto, alg, null, true);
        const privateKeyJwk = await privateKey.getJwkKey(KeyExport.Private);
        const importedPrivateKey = await cryptoObj.crypto.subtle
        .importKey('jwk', privateKeyJwk, normalizedAlgorithm, true, keyOperations);

        const publicKey = new DidKey(cryptoObj.crypto, alg, null, true);
        const publicKeyJwk = await publicKey.getJwkKey(KeyExport.Public);
        const importedPublicKey = await cryptoObj.crypto.subtle
        .importKey('jwk', publicKeyJwk, normalizedAlgorithm, true, keyOperations);

        const privateKeyObject = new KeyObject(KeyType.EC, importedPrivateKey);
        const publicKeyObject = new KeyObject(KeyType.EC, importedPublicKey);

        const bits: any = await cryptoObj.crypto.subtle.deriveBits({
          name: 'ECDH',
          public: publicKeyObject.publicKey
        }, privateKeyObject.privateKey, 128);
        expect(bits).toBeDefined();
        expect(bits.byteLength).toBe(16);
      });
      done();
    });
  });
});
