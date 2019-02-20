import PairwiseKey from '../../lib/crypto/PairwiseKey';
import DidKey from '../../lib/crypto/DidKey';
import { KeyType } from '../../lib/crypto/KeyType';
import { KeyUse } from '../../lib/crypto/KeyUse';
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
    it('Throw exception.', () => {
      let masterKey: Buffer = Buffer.alloc(32, 2);
      const alg = { name: 'ECDSA', namedCurve: 'K-256', hash: { name: 'SHA-256' } };
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      try {
        key.generate(masterKey, crypto, alg, KeyType.Oct, KeyUse.Signature)
        .catch(() => {
          fail('The catch should not happen because exception occurs before promise is generated');
        });
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
              })
              .catch((err) => {
                fail(`Error occured: '${err}'`);
              });
            })
            .catch((err) => {
              fail(`Error occured: '${err}'`);
            });
          })
          .catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        })
        .catch((err) => {
          fail(`Error occured: '${err}'`);
        });
      })
      .catch((err) => {
        fail(`Error occured: '${err}'`);
      });
    });

  });

  fdescribe('components for prime generator', () => {
    it('Generate a candidate for prime', (done) => {
      let masterKey: Buffer = Buffer.alloc(32, 1);
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      key.generateDeterministicNumberForPrime(crypto, 1024, masterKey, 'www.peer.com').then((p) => {
        expect(128).toBe(p.byteLength);

        key.generateDeterministicNumberForPrime(crypto, 1024, p, 'www.peer.com').then((q) => {
          expect(128).toBe(q.byteLength);
          expect(p).not.toBe(q);
          done();
        })
        .catch((err) => {
          fail(`Error occured: '${err}'`);
        });
      })
      .catch((err) => {
        fail(`Error occured: '${err}'`);
      });
    });

    it('Generate a prime', (done) => {
      let masterKey: Buffer = Buffer.alloc(32, 1);
      let key = new PairwiseKey('1234567890', 'www.peer.com');
      key.generateDeterministicNumberForPrime(crypto, 1024, masterKey, 'www.peer.com').then((p) => {
        expect(128).toBe(p.byteLength);

        let pArray = Array.from(p);  // new Uint8Array(p);
        let primeP: bigInt.BigIntegerStatic = key.generatePrime(pArray);
        console.log(primeP.toString());
        done();
      })
      .catch((err) => {
        fail(`Error occured: '${err}'`);
      });
    });
  });
});
