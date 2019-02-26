import DidKey from '../../lib/crypto/DidKey';
import { KeyType } from '../../lib/crypto/KeyType';
import { KeyUse } from '../../lib/crypto/KeyUse';
import WebCrypto from 'node-webcrypto-ossl';
const pairwiseKeys = require('./Pairwise.RSA.json');

const crypto = new WebCrypto();

describe('DidKey Pairwise keys RSA', () => {

  describe('Test Pairwise key generation', () => {
    let seed = Buffer.from('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');
    it('Check PairwiseId generation', (done) => {
      let inx: number = 0;
      let nrIds: number = 2;
      let ids: string[] = [];
      for (inx = 0; inx < nrIds; inx++) {
        ids.push(`peerid-${inx}`);
      }

      let did: string = 'abcdef';
      let alg = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 1024, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-256' } };
      let didKey: DidKey = new DidKey(crypto, alg, KeyType.RSA, KeyUse.Signature, null);
      inx = 0;
      let testPromise = new Promise((resolve, reject) => {
        for (let pwid of ids) {
          didKey.generatePairwise(seed, did, pwid).then((pairwiseKey: DidKey) => {
            pairwiseKey.jwkKey.then((jwk) => {
              // console.log(`{ pwid: '${pwid}', inx: ${inx++}, key: '${jwk.n}'},`);
              pairwiseKeys.forEach((element: any) => {
                if (element.pwid === pwid) {
                  // console.log(`Check ${element.inx}: ${element.key} == ${jwk.n}`);
                  expect(element.key).toBe(jwk.n);
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
      });
      testPromise
    .finally(() => {
      done();
    })
    .catch((err) => {
      fail(`Error occured: '${err}'`);
    });
    });
  });
});
