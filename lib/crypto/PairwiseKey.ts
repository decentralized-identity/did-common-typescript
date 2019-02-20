
const elliptic = require('elliptic');
const BN = require('bn.js');
import base64url from 'base64url';
import DidKey from './DidKey';
import { KeyType } from './KeyType';
import { KeyUse } from './KeyUse';
import { BigIntegerStatic } from 'big-integer';
const bigInt = require('big-integer');

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
  private _key: DidKey | undefined;

  /**
   * Buffer used for prime generation
   */
  private _deterministicKey: Buffer = Buffer.from('');
  /**
   * Get the id for the pairwise key
   */
  public get id () {
    return this._id;
  }

  /**
   * Get the id for the pairwise key
   */
  public get key (): DidKey | undefined {
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
    this._key = undefined;
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
      case KeyType.RSA:
        return this.generateRsaPairwiseKey(didMasterKey, crypto, algorithm, keyType, keyUse, exportable);
    }

    throw new Error(`Pairwise key for key type ${keyType} is not supported`);
  }

  /**
   * Generate a deterministic number that can be used as prime
   * @param crypto The crypto object.
   * @param keySize Desired key size
   * @param didMasterKey The DID masterkey
   * @param peerId The peer id
   */
  public generateDeterministicNumberForPrime (crypto: any, primeSize: number, didMasterKey: Buffer, peerId: string): Promise<Buffer> {
    let numberOfRounds: number = primeSize / (8 * 64);
    this._deterministicKey = Buffer.from('');
    let rounds: Array<(crypto: any, inx: number, key: Buffer, data: Buffer) => Promise<Buffer>> = [];
    for (let inx = 0; inx < numberOfRounds ; inx++) {
      rounds.push((crypto: any, inx: number, key: Buffer, data: Buffer) => {
        return this.generateHashForPrime(crypto, inx, key, data);
      });
    }

    return this.executeRounds(crypto, rounds, 0, didMasterKey, Buffer.from(peerId));
  }

  /**
   * Generate a hash used as component for prime number
   * @param crypto The crypto object.
   * @param key Signature key
   * @param data Data to sign
   */
  private generateHashForPrime (crypto: any, inx: number, key: Buffer, data: Buffer): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      const alg = { name: 'hmac', hash: { name: 'SHA-512' } };
      let deterministicNumber = new DidKey(crypto, alg, KeyType.Oct, KeyUse.Signature, key, true);
      return deterministicNumber.jwkKey.then((jwk) => {
        return deterministicNumber.sign(data).then((signature) => {
          this._deterministicKey = Buffer.concat([this._deterministicKey, Buffer.from(signature)]);
          return resolve(this._deterministicKey);
        });
      });
    });
  }

  /**
   * Execute all rounds
   * @param rounds Array of functions to execute
   * @param inx Current step
   * @param key Key to sign
   * @param data Data to sign
   */
  private executeRounds (crypto: any, rounds: Array<(crypto: any, inx: number, key: Buffer, data: Buffer) =>
    Promise<Buffer>>, inx: number, key: Buffer, data: Buffer): Promise<Buffer> {
    return rounds[inx](crypto, inx, key, data).then((signature: Buffer) => {
      if (inx + 1 === rounds.length) {
        return this._deterministicKey;
      } else {
        return this.executeRounds(crypto, rounds, inx + 1, key, Buffer.from(signature)).then((signature: any) => {
          return this._deterministicKey;
        });
      }
    });
  }

  /**
   * Generate a prime number from the seed
   * @param primeSeed seed for prime generator
   */
  generatePrime (primeSeed: Array<number>): BigIntegerStatic {
    // make sure candidate is uneven
    primeSeed[primeSeed.length - 1] |= 0x1;
    let prime = bigInt.fromArray(primeSeed, 256, false);
    return prime;
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

  /**
   * Generate the RSA pairwise Key.
   * @param didMasterKey The master key for this did.
   * @param crypto The crypto object.
   * @param algorithm Intended algorithm to use for the key.
   * @param keyType Key type.
   * @param keyUse Key usage.
   * @param exportable True if the key is exportable.
   */
  private generateRsaPairwiseKey (
    didMasterKey: Buffer,
    crypto: any,
    algorithm: any,
    keyType: KeyType,
    keyUse: KeyUse,
    exportable: boolean = true): Promise<DidKey> {
      // Generate peer key
    let minimumKeySize = 2048;
    let keySize = minimumKeySize;
    if (algorithm.modulusLength) {
      keySize = algorithm.modulusLength;
      if (keySize && keySize < minimumKeySize) {
        keySize = minimumKeySize;
      } else {
        keySize = minimumKeySize;
      }
    }
/*
    return this.generateDeterministicNumberForPrime(crypto, keySize/2, didMasterKey, this._peerId).then((pSeed: Buffer) => {

    })
    */

    const alg = { name: 'hmac', hash: { name: 'SHA-512' } };
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
