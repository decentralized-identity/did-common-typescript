import DidKey from '../../lib/crypto/DidKey';
import { KeyType } from '../../lib/crypto/KeyType';
import { KeyUse } from '../../lib/crypto/KeyUse';
import WebCrypto from 'node-webcrypto-ossl';
const pairwiseKeys = require('./Pairwise.EC.json');

const crypto = new WebCrypto();

describe('DidKey Pairwise keys EC', () => {

  describe('Test Pairwise key generation', () => {
    it('Test P-256', (done) => {
      const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } };

      // Generate the key pair
      let didKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null, true);

      didKey.jwkKey.then((ecKey1) => {
        expect(ecKey1).not.toBeNull();
        expect('P-256').toBe(ecKey1.crv);
        expect('EC').toBe(ecKey1.kty);
        done();
      })
      .catch((err) => {
        fail(`Error occured: '${err}'`);
      });

    });

    let seed = Buffer.from('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');

    it('Check PairwiseId generation uniqueness', () => {
      let inx: number = 0;
      let results: string[] = [];
      const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
      let didKey: DidKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null);
      for (inx = 0 ; inx < 1000; inx++) {
        didKey.generatePairwise(seed, `did=${inx}`, 'peer').then((pairwiseKey: DidKey) => {
          pairwiseKey.jwkKey.then((jwk) => {
            results.push(jwk.d);
            // console.log(`Check ${jwk.d} ${results.length}`);
            expect(1).toBe(results.filter(element => element === jwk.d).length);
          })
          .catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        })
        .catch((err) => {
          fail(`Error occured: '${err}'`);
        });
      }
    });

    it('Check PairwiseId generation uniqueness with different seed', (done) => {
      let inx: number = 0;
      let nrIds: number = 100;
      let ids: string[] = [];
      for (inx = 0; inx < nrIds; inx++) {
        ids.push(`peerid-${inx}`);
      }

      let did: string = 'abcdef';
      let seed = Buffer.from('yprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');
      const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
      let didKey: DidKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null);
      inx = 0;
      for (let pwid of ids) {
        didKey.generatePairwise(seed, did, pwid).then((pairwiseKey: DidKey) => {
          pairwiseKey.jwkKey.then((jwk) => {
            // console.log(`{ pwid: '${pwid}', inx: ${inx++}, key: '${jwk.d}'},`);
            pairwiseKeys.forEach((element: any) => {
              if (element.pwid === pwid) {
                // console.log(`Check ${element.inx}: ${element.key} == ${jwk.d}`);
                expect(element.key).not.toBe(jwk.d);
                expect(0).toBe(pairwiseKeys.filter((element: any) => element === jwk.d).length);
                return;
              }
            });
          })
          .catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        })
        .catch((err) => {
          fail(`Error occured: '${err}'`);
        });
      }

      done();
    });

    it('Check PairwiseId generation uniqueness with different peer', (done) => {
      let inx: number = 0;
      let nrIds: number = 100;
      let ids: Promise<string>[] = [];
      for (inx = 0; inx < nrIds; inx++) {
        // ids.push(Promise.resolve(`${inx}`));
        ids.push(new Promise((resolve, reject) => {
          let did: string = 'abcdef';
          const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
          let didKey: DidKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null);
          let id = `${inx}`;
          didKey.generatePairwise(seed, did, id).then((pairwiseKey: DidKey) => {
            return pairwiseKey.jwkKey;
          }).then((jwk) => {
            // console.log(`{ "pwid": "${id}", "key": "${jwk.d}"},`);
            let element = pairwiseKeys.filter((item: any) => {
              return item.pwid === id;
            });

            console.log(`${id}: Check ${element[0].pwid}: ${element[0].key} == ${jwk.d}`);
            expect(element[0].key).toBe(jwk.d);
            expect(1).toBe(pairwiseKeys.filter((element: any) => element.key === jwk.d).length);
            resolve();
          }).catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        }));
      }

      Promise.all(ids).then((elements) => {
        console.log('done');
        done();
      }).catch((err) => {
        fail(`Error occured: '${err}'`);
      });
    });

    it('Check PairwiseId generation uniqueness with different did', (done) => {
      let inx: number = 0;
      let nrIds: number = 100;
      let ids: string[] = [];
      for (inx = 0; inx < nrIds; inx++) {
        ids.push(`peerid-${inx}`);
      }

      let did: string = 'abcdef';
      let seed = Buffer.from('yprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');
      const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
      inx = 0;
      let didKey: DidKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null);
      for (let pwid of ids) {
        didKey.generatePairwise(seed, did, pwid).then((pairwiseKey: DidKey) => {
          pairwiseKey.jwkKey.then((jwk) => {
            // console.log(`{ pwid: '${pwid}', inx: ${inx++}, key: '${jwk.d}'},`);
            pairwiseKeys.forEach((element: any) => {
              if (element.pwid === pwid) {
                // console.log(`Check ${element.inx}: ${element.key} == ${jwk.d}`);
                expect(element.key).not.toBe(jwk.d);
                expect(0).toBe(pairwiseKeys.filter((element: any) => element === jwk.d).length);
                return;
              }
            });
          })
          .catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        })
        .catch((err) => {
          fail(`Error occured: '${err}'`);
        });
      }

      done();
    });

    it('Check PairwiseId generation', (done) => {
      let inx: number = 0;
      let nrIds: number = 100;
      let ids: string[] = [];
      for (inx = 0; inx < nrIds; inx++) {
        ids.push(`peerid-${inx}`);
      }

      let did: string = 'abcdef';
      const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
      let didKey: DidKey = new DidKey(crypto, alg, KeyType.EC, KeyUse.Signature, null);
      inx = 0;
      for (let pwid of ids) {
        didKey.generatePairwise(seed, did, pwid).then((pairwiseKey: DidKey) => {
          pairwiseKey.jwkKey.then((jwk) => {
            // console.log(`{ pwid: '${pwid}', inx: ${inx++}, key: '${jwk.d}'},`);
            pairwiseKeys.forEach((element: any) => {
              if (element.pwid === pwid) {
                // console.log(`Check ${element.inx}: ${element.key} == ${jwk.d}`);
                expect(element.key).toBe(jwk.d);
                return;
              }
            });
          })
          .catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        })
        .catch((err) => {
          fail(`Error occured: '${err}'`);
        });
      }

      done();
    });

  });
});
