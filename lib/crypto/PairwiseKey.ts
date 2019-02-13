
const elliptic = require('elliptic');
const BN = require('bn.js');
import base64url from 'base64url';
import DidKey from './DidKey';
import { KeyType } from './KeyType';
import { KeyUse } from './KeyUse';

/**
 * Class to model a pairwise key
 */
export default class PairwiseKey {
  /**
   * Get the index for pairwise key
   */
  private _id: string;

  /**
   * Get the pairwise id
   */
  private _peerId: string;

  /**
   * Get the pairwise key
   */
  private _key: DidKey | null;

  /**
   * Get the id for the pairwise key
   */
  public get id () {
    return this._id;
  }

  /**
   * Get the id for the pairwise key
   */
  public get key (): DidKey | null {
    return this._key;
  }

  /**
   * Create an instance of PairwiseKey.
   * @param did The DID.
   * @param peerId The peer id.
   */
  constructor (did: string, peerId: string) {
    this._id = `${did}-${peerId}`;
    this._peerId = peerId;
    this._key = null;
  }

  /**
   * Generate the pairwise Key.
   * @param didMasterKey The master key for this did.
   * @param crypto The crypto object.
   * @param algorithm Intended algorithm to use for the key.
   * @param keyType Key type.
   * @param keyUse Key usage.
   * @param exportable True if the key is exportable.
   */
  public generate (
    didMasterKey: Buffer,
    crypto: any,
    algorithm: any,
    keyType: KeyType,
    keyUse: KeyUse,
    exportable: boolean = true): Promise<DidKey> {
    switch (keyType) {
      case KeyType.EC:
        return this.generateEcPairwiseKey(didMasterKey, crypto, algorithm, keyType, keyUse, exportable);
    }

    throw new Error(`Pairwise key for key type ${keyType} is not supported`);
  }

  /**
   * Generate the EC pairwise Key.
   * @param didMasterKey The master key for this did.
   * @param crypto The crypto object.
   * @param algorithm Intended algorithm to use for the key.
   * @param keyType Key type.
   * @param keyUse Key usage.
   * @param exportable True if the key is exportable.
   */
  private generateEcPairwiseKey (
    didMasterKey: Buffer,
    crypto: any,
    algorithm: any,
    keyType: KeyType,
    keyUse: KeyUse,
    exportable: boolean = true): Promise<DidKey> {
      // Generate peer key
    const alg = { name: 'hmac', hash: { name: 'SHA-256' } };
    let hashDidKey = new DidKey(crypto, alg, KeyType.Oct, KeyUse.Signature, didMasterKey, true);
    return hashDidKey.jwkKey.then((jwkHmacKey) => {
      return hashDidKey.sign(Buffer.from(this._peerId))
        .then((signature: any) => {
          let ec = new elliptic.ec('secp256k1');
          let privKey = new BN(Buffer.from(signature));
          privKey = privKey.umod(ec.curve.n);
          let pubKey = ec.g.mul(privKey);

          let d = privKey.toArrayLike(Buffer, 'be', 32);
          let x = pubKey.x.toArrayLike(Buffer, 'be', 32);
          let y = pubKey.y.toArrayLike(Buffer, 'be', 32);
          let jwk = {
            crv: 'K-256',
            d: base64url.encode(d),
            x: base64url.encode(x),
            y: base64url.encode(y),
            kty: 'EC'
          };

          this._key = new DidKey(crypto, algorithm, keyType, keyUse, jwk, exportable);
          return this._key;
        });
    });

  }
}
