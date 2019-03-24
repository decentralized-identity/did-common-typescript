import PairwiseKey from '../../lib/crypto/PairwiseKey';
import DidKey from '../../lib/crypto/DidKey';
import { KeyType } from '../../lib/crypto/KeyType';
import { KeyUse } from '../../lib/crypto/KeyUse';
import { KeyExport } from '../../lib/crypto/KeyExport';
import WebCrypto from 'node-webcrypto-ossl';
import bigInt from 'big-integer';

const crypto = new WebCrypto();

describe('PairwiseKey', () => {
  it('should construct a new instance', () => {
    const key = new PairwiseKey('1234567890', 'www.peer.com');
    expect('1234567890-www.peer.com').toBe(key.id);
    expect(key.key).toBeUndefined();
  });

  it('should throw when generating key for unsupported key type.', async (done) => {
    const masterKey: Buffer = Buffer.alloc(32, 2);
    const alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };
    const key = new PairwiseKey('1234567890', 'www.peer.com');
    try {
      await key.generate(masterKey, crypto, alg, KeyType.Oct, KeyUse.Signature);
      fail('Should not reach because exception must occur');
    } catch (error) {
      expect(error).toEqual(jasmine.any(Error));
      expect(error.message).toEqual('Pairwise key for key type oct is not supported');
      done();
    }
  });

  it('should throw when generating key for unsupported curve.', async (done) => {
    const masterKey: Buffer = Buffer.alloc(32, 1);
    const key = new PairwiseKey('1234567890', 'www.peer.com');
    const alg = { name: 'ECDSA', namedCurve: 'X-256', hash: { name: 'SHA-256' } };
    try {
      await key.generate(masterKey, crypto, alg, KeyType.EC, KeyUse.Signature, true);
    } catch (error) {
      expect(error.message).toBe('Curve X-256 is not supported');
      done();
    }
  });

  it('should generate key pair for K-256.', async (done) => {
    const masterKey: Buffer = Buffer.alloc(32, 1);
    const key = new PairwiseKey('1234567890', 'www.peer.com');
    const alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };
    let didKey: DidKey = await key.generate(masterKey, crypto, alg, KeyType.EC, KeyUse.Signature, true);
    expect(didKey).toBeDefined();
    const jwk = await didKey.getJwkKey(KeyExport.Private);
    const data = 'abcdefghij';
    const signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
    // Make sure there is only the public key
    jwk.d = undefined;
    didKey = new DidKey(crypto, alg, jwk, true);
    let correct: boolean = await didKey.verify(Buffer.from(data), signature);
    expect(correct).toBeTruthy();
    done();
  });

  it('should generate a suitable deterministic number', async (done) => {
    const masterKey: Buffer = Buffer.alloc(32, 1);
    const key = new PairwiseKey('1234567890', 'www.peer.com');
    const p: Buffer = await key.generateDeterministicNumberForPrime(crypto, 1024, masterKey, Buffer.from('www.peer.com'));
    expect(p.byteLength).toBe(128);

    const q: Buffer = await key.generateDeterministicNumberForPrime(crypto, 1024, p, Buffer.from('www.peer.com'));
    expect(q.byteLength).toBe(128);
    expect(p).not.toBe(q);
    done();
  });

  it('should generate a suitable prime', async (done) => {
    const masterKey: Buffer = Buffer.alloc(32, 1);
    const key = new PairwiseKey('1234567890', 'www.peer.com');
    const p: Buffer = await key.generateDeterministicNumberForPrime(crypto, 1024, masterKey, Buffer.from('www.peer.com'));
    expect(p.byteLength).toBe(128);
    const pArray = Array.from(p);
    const primeP: bigInt.BigIntegerStatic = key.generatePrime(pArray);
    expect(primeP.toString()).toEqual(
    '15040213270024811204597832011188743880332713683453624219109518111' +
    '15882122109612316569074379816705253086987900220803919960986470451' +
    '12034113434039176852012602839641796910170796600486069886405962368' +
    '89039540888039746828026068325210180611327600723007359851604931839' +
    '5807068211501529212801352936184418259227712514547');
    expect(key.primeTests).toBeGreaterThan(0);
    done();
  });

  it('should generate a key pair for signing', async (done) => {
    const masterKey: Buffer = Buffer.alloc(32, 1);
    const key = new PairwiseKey('1234567890', 'www.peer.com');
    const alg = { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
    const didKey: DidKey = await key.generate(masterKey, crypto, alg, KeyType.RSA, KeyUse.Signature, true);
    expect(didKey).toBeDefined();
    expect(didKey.exportable).toBeTruthy();
    const data = 'the lazy dog jumped over ... forgot the rest';
    const signature: ArrayBuffer = await didKey.sign(Buffer.from(data));
    const correct: boolean = await didKey.verify(Buffer.from(data), signature);
    expect(correct).toBeTruthy();
    done();
  });

  it('should generate a non-exportable RSA key', async (done) => {
    const masterKey: Buffer = Buffer.alloc(32, 1);
    const key = new PairwiseKey('1234567890', 'www.peer.com');
    const alg = { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
    const didKey: DidKey = await key.generate(masterKey, crypto, alg, KeyType.RSA, KeyUse.Signature, false);
    expect(didKey).toBeDefined();
    expect(didKey.exportable).toBeFalsy();
    done();
  });

  it('should generate a non-exportable elliptic curve key', async (done) => {
    const masterKey: Buffer = Buffer.alloc(32, 1);
    const key = new PairwiseKey('1234567890', 'www.peer.com');
    const alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };
    const didKey: DidKey = await key.generate(masterKey, crypto, alg, KeyType.EC, KeyUse.Signature, false);
    expect(didKey).toBeDefined();
    expect(didKey.exportable).toBeFalsy();
    done();
  });
});
