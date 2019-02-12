import PairwiseKey from '../../lib/crypto/PairwiseKey';
import DidKey from '../../lib/crypto/DidKey';
import { KeyType } from '../../lib/crypto/KeyType';
import { KeyUse } from '../../lib/crypto/KeyUse';
import WebCrypto from 'node-webcrypto-ossl';

const crypto = new WebCrypto();

describe('PairwiseKey', () => {
  describe('Test constructor', () => {
    it('Should set the right properties.', () => {
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      expect('1234567890-www.peer.com').toBe(key.id);
      expect(key.key).toBeNull();
    });

  });

  describe('generate', () => {
    it('Throw exception.', () => {
      let masterKey: Buffer = Buffer.alloc(32, 2);
      const alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      try {
        key.generate(masterKey, crypto, alg, KeyType.Oct, KeyUse.Signature);
      } catch (err) {
        expect(err).toEqual(jasmine.any(Error));
        expect('Pairwise key for key type oct is not supported').toBe(err.message);
      }
    });

    it('Generate key pair.', (done) => {
      let masterKey: Buffer = Buffer.alloc(32, 1);
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      const alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };
      key.generate(masterKey, crypto, alg, KeyType.EC, KeyUse.Signature, true).then((didKey: DidKey) => {
        expect(didKey).toBeDefined();
        didKey.jwkKey.then((jwk) => {
          const data = 'abcdefghij';
          didKey.sign(Buffer.from(data)).then((signature: ArrayBuffer) => {
            // Make sure there is only the public key
            jwk.d = undefined;
            didKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, jwk, true);
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
