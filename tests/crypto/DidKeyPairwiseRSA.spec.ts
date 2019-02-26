import DidKey from '../../lib/crypto/DidKey';
import { KeyType } from '../../lib/crypto/KeyType';
import { KeyUse } from '../../lib/crypto/KeyUse';
import WebCrypto from 'node-webcrypto-ossl';
const pairwiseKeys = require('./Pairwise.RSA.json');

const crypto = new WebCrypto();

describe('DidKey Pairwise keys RSA', () => {

  describe('Test Pairwise key generation', () => {
    let seed = Buffer.from('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');
    beforeEach(() => {
      jasmine.DEFAULT_TIMEOUT_INTERVAL = 60000;
    });

    it('Check PairwiseId generation uniqueness with different peer', (done) => {
      let inx: number = 0;
      let nrIds: number = 2;
      let ids: Promise<string>[] = [];
      for (inx = 0; inx < nrIds; inx++) {
        ids.push(Promise.resolve(`${inx}`));
      }

      let did: string = 'abcdef';
      let alg = { name: 'RSASSA-PKCS1-v1_5', modulusLength: 1024, publicExponent: new Uint8Array([0x01, 0x00, 0x01]), hash: { name: 'SHA-256' } };
      let didKey: DidKey = new DidKey(crypto, alg, KeyType.RSA, KeyUse.Signature, null);

      Promise.all(ids).then((elements) => {
        elements.forEach((id) => {
          didKey.generatePairwise(seed, did, id).then((pairwiseKey: DidKey) => {
            return pairwiseKey.jwkKey;
          }).then((jwk) => {
            console.log(`{ "pwid": "${id}", "key": "${jwk.n}"},`);
            let element = pairwiseKeys.filter((item: any) => {
              return item.pwid === id;
            });

            console.log(`${id}: Check ${element[0].pwid}: ${element[0].key} == ${jwk.n}`);
            expect(element[0].key).toBe(jwk.n);
            expect(1).toBe(pairwiseKeys.filter((element: any) => element.key === jwk.n).length);
          }).catch((err) => {
            fail(`Error occured: '${err}'`);
          });
        });
      }).finally(() => {
        done();
      }).catch((err) => {
        fail(`Error occured: '${err}'`);
      });
    });
  });
});
