import PairwiseKey from '../../lib/crypto/PairwiseKey';
import DidKey from '../../lib/crypto/DidKey';
import { KeyType } from '../../lib/crypto/KeyType';
import { KeyUse } from '../../lib/crypto/KeyUse';
import { KeyExport } from '../../lib/crypto/KeyExport';
import WebCrypto from 'node-webcrypto-ossl';
import bigInt from 'big-integer';

const crypto = new WebCrypto();

describe('PairwiseKey', () => {
  describe('Test constructor', () => {
    it('Should set the right properties.', () => {
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      expect('1234567890-www.peer.com').toBe(key.id);
      expect(key.key).toBeUndefined();
    });
  });

  describe('generate', () => {
    it('Throw exception.', async () => {
      let masterKey: Buffer = Buffer.alloc(32, 2);
      const alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      try {
        await key.generate(masterKey, crypto, alg, KeyType.Oct, KeyUse.Signature);
        fail('Should not reach because exception must occur');
      } catch (err) {
        expect(err).toEqual(jasmine.any(Error));
        expect('Pairwise key for key type oct is not supported').toBe(err.message);
      }
    });

    it('Throw unsupported curve.', async (done) => {
      let masterKey: Buffer = Buffer.alloc(32, 1);
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      const alg = { name: 'ECDSA', namedCurve: 'X-256', hash: { name: 'SHA-256' } };
      let seenException = false;
      await key.generate(masterKey, crypto, alg, KeyType.EC, KeyUse.Signature, true)
      .catch((err) => {
        expect('Curve X-256 is not supported').toBe(err.message);
        seenException = true;
        done();
      });

      if (!seenException) {
        fail('Should throw exception');
      }
    });

    it('Generate key pair for K-256.', async (done) => {
      let masterKey: Buffer = Buffer.alloc(32, 1);
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      const alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };
      let didKey: DidKey = await key.generate(masterKey, crypto, alg, KeyType.EC, KeyUse.Signature);
      expect(didKey).toBeDefined();
      let jwk = await didKey.getJwkKey(KeyExport.Private);
      const data = 'abcdefghij';
      let signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
            // Make sure there is only the public key
      jwk.d = undefined;
      didKey = new DidKey(crypto, alg, jwk, true);
      let correct: boolean = await didKey.verify(Buffer.from(data), signature);
      expect(true).toBe(correct);
      done();
    });

  });

  describe('components for prime generator', () => {

    it('Generate a candidate for prime', async (done) => {
      let masterKey: Buffer = Buffer.alloc(32, 1);
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      let p: Buffer = await key.generateDeterministicNumberForPrime(crypto, 1024, masterKey, Buffer.from('www.peer.com'));
      expect(128).toBe(p.byteLength);

      let q: Buffer = await key.generateDeterministicNumberForPrime(crypto, 1024, p, Buffer.from('www.peer.com'));
      expect(128).toBe(q.byteLength);
      expect(p).not.toBe(q);
      done();
    });

    it('Generate a prime', async (done) => {
      let masterKey: Buffer = Buffer.alloc(32, 1);
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      let p: Buffer = await key.generateDeterministicNumberForPrime(crypto, 1024, masterKey, Buffer.from('www.peer.com'));
      expect(128).toBe(p.byteLength);

      let pArray = Array.from(p);
      let primeP: bigInt.BigIntegerStatic = key.generatePrime(pArray);
        // tslint:disable-next-line:max-line-length
      expect('150402132700248112045978320111887438803327136834536242191095181111588212210961231656907437981670525308698790022080391996098647045112034113434039176852012602839641796910170796600486069886405962368890395408880397468280260683252101806113276007230073598516049318395807068211501529212801352936184418259227712514547')
        .toBe(primeP.toString());
      expect(key.primeTests).toBeGreaterThan(0);
      done();
    });
  });

  describe('RSA key generator', () => {
    beforeEach(() => {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });

    it('Generate a key pair for signing',async (done) => {
      let masterKey: Buffer = Buffer.alloc(32, 1);
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      let alg = { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
      let didKey: DidKey = await key.generate(masterKey, crypto, alg, KeyType.RSA, KeyUse.Signature, true);
      expect(didKey).toBeDefined();
      let data = 'the lazy dog jumped over ... forgot the rest';
      let signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
      let correct: boolean = await didKey.verify(Buffer.from(data), signature);
      expect(true).toBe(correct);
      done();
    });

  });

});
