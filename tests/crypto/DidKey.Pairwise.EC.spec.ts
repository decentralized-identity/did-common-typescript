import WebCrypto from 'node-webcrypto-ossl';
import DidKey from '../../lib/crypto/DidKey';
import { KeyExport } from '../../lib/crypto/KeyExport';

const pairwiseKeys = require('./Pairwise.EC.json');
const crypto = new WebCrypto();
const seed = Buffer.from('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');

describe('DidKey - elliptic curve pairwise keys', () => {

  let originalTimeout = jasmine.DEFAULT_TIMEOUT_INTERVAL;

  beforeEach(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
  });

  afterEach(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = originalTimeout;
  });

  it(`should throw when generating keys using an unsupported key type of 'oct'`, async (done) => {
    const pwDidKey: DidKey = new DidKey(crypto, { name: 'hmac', hash: 'SHA-256' }, null);
    await pwDidKey.generatePairwise(Buffer.from('abcdefg'), 'did:test:something', 'did:test:peer')
    .catch((err) => {
      expect(`Pairwise key for type 'oct' is not supported.`).toBe(err.message);
    });
    done();
  });

  it('should return a P-256 key', async (done) => {
    const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } };

    // Generate the key pair
    let didKey = new DidKey(crypto, alg, null, true);

    let ecKey1 = await didKey.getJwkKey(KeyExport.Private);
    expect(ecKey1).not.toBeNull();
    expect('P-256').toBe(ecKey1.crv);
    expect('EC').toBe(ecKey1.kty);
    done();
  });

  it('should generate a pairwise identifier', async (done) => {
    const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
    let didKey: DidKey = new DidKey(crypto, alg, null);
    let pairwiseKey1: DidKey = await didKey.generatePairwise(seed, `did:test`, 'peer');
    // return the same
    let pairwiseKey2: DidKey = await didKey.generatePairwise(seed, `did:test`, 'peer');
    expect(pairwiseKey1).toBe(pairwiseKey2);
    done();
  });

  it('should generate unique pairwise identifiers', async (done) => {
    const results: string[] = [];
    const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
    const didKey: DidKey = new DidKey(crypto, alg, null);
    for (let index = 0 ; index < 1000; index++) {
      const pairwiseKey: DidKey = await didKey.generatePairwise(seed, `did=${index}`, 'peer');
      const jwk = await pairwiseKey.getJwkKey(KeyExport.Private);
      results.push(jwk.d);
      // console.log(`Check ${jwk.d} ${results.length}`);
      expect(1).toBe(results.filter(element => element === jwk.d).length);
    }
    done();
  });

  it('should generate unique pairwise identifiers using a different seed', async (done) => {
    let inx: number = 0;
    let nrIds: number = 100;
    let ids: string[] = [];
    for (inx = 0; inx < nrIds; inx++) {
      ids.push(`peerid-${inx}`);
    }

    let did: string = 'abcdef';
    let seed = Buffer.from('yprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');
    const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
    let didKey: DidKey = new DidKey(crypto, alg, null);
    inx = 0;
    for (let pwid of ids) {
      let pairwiseKey: DidKey = await didKey.generatePairwise(seed, did, pwid);
      let jwk = await pairwiseKey.getJwkKey(KeyExport.Private);

      // console.log(`{ pwid: '${pwid}', inx: ${inx++}, key: '${jwk.d}'},`);
      expect(0).toBe(pairwiseKeys.filter((element: any) =>
        element.key === jwk.d).length);
    }

    done();
  });

  it('should generate unique pairwise identifiers using a different peer', async (done) => {
    let inx: number = 0;
    let nrIds: number = 100;
    for (inx = 0; inx < nrIds; inx++) {
      let did: string = 'abcdef';
      const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
      let didKey: DidKey = new DidKey(crypto, alg, null);
      let id = `${inx}`;
      let pairwiseKey: DidKey = await didKey.generatePairwise(seed, did, id);
      let jwk = await pairwiseKey.getJwkKey(KeyExport.Private);
      expect(jwk.kid).toBeDefined();

      console.log(`{ "pwid": "${id}", "key": "${jwk.d}"},`);
      // console.log(`${id}: Check ${pairwiseKeys[inx].pwid}: ${pairwiseKeys[inx].key} == ${jwk.d}`);
      expect(pairwiseKeys[inx].key).toBe(jwk.d);
      expect(1).toBe(pairwiseKeys.filter((element: any) => element.key === jwk.d).length);
    }

    done();
  });

  it('should generate unique pairwise identifiers for a different decentralized identifier', async (done) => {
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
    let didKey: DidKey = new DidKey(crypto, alg, null);
    for (let pwid of ids) {
      let pairwiseKey: DidKey = await didKey.generatePairwise(seed, did, pwid);
      let jwk = await pairwiseKey.getJwkKey(KeyExport.Private);
      expect(jwk.kid).toBeDefined();
      // console.log(`{ pwid: '${pwid}', inx: ${inx++}, key: '${jwk.d}'},`);
      pairwiseKeys.forEach((element: any) => {
        if (element.pwid === pwid) {
          // console.log(`Check ${element.inx}: ${element.key} == ${jwk.d}`);
          expect(element.key).not.toBe(jwk.d);
          expect(0).toBe(pairwiseKeys.filter((element: any) => element === jwk.d).length);
          return;
        }
      });
    }

    done();
  });

  it('should generate unique private keys for pairwise identifiers', async (done) => {
    let inx: number = 0;
    let nrIds: number = 100;
    let ids: string[] = [];
    for (inx = 0; inx < nrIds; inx++) {
      ids.push(`peerid-${inx}`);
    }

    let did: string = 'abcdef';
    const alg = { name: 'ECDSA', namedCurve: 'P-256K', hash: { name: 'SHA-256' } };
    let didKey: DidKey = new DidKey(crypto, alg, null);
    inx = 0;
    for (let pwid of ids) {
      let pairwiseKey: DidKey = await didKey.generatePairwise(seed, did, pwid);
      let jwk = await pairwiseKey.getJwkKey(KeyExport.Private);
      expect(jwk.kid).toBeDefined();
      // console.log(`{ pwid: '${pwid}', inx: ${inx++}, key: '${jwk.d}'},`);
      pairwiseKeys.forEach((element: any) => {
        if (element.pwid === pwid) {
          // console.log(`Check ${element.inx}: ${element.key} == ${jwk.d}`);
          expect(element.key).toBe(jwk.d);
          return;
        }
      });
    }

    done();
  });
});
