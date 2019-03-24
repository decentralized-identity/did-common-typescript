import base64url from 'base64url';
import { BigIntegerStatic } from 'big-integer';
import DidKey from './DidKey';
import { KeyExport } from './KeyExport';
import { KeyType } from './KeyType';
import { KeyUse } from './KeyUse';

const bigInt = require('big-integer');
const BN = require('bn.js');

// Create and initialize EC context
const elliptic = require('elliptic').ec;
const secp256k1 = new elliptic('secp256k1');

const SUPPORTED_CURVES = ['K-256', 'P-256K'];

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
   * Get the number of prime tests
   */
  private _numberOfPrimeTests: number;

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
   * Get the number of tests needed for prime generation
   */
  public get primeTests (): number {
    return this._numberOfPrimeTests;
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
    this._numberOfPrimeTests = 0;
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
  public async generate (
    didMasterKey: Buffer,
    crypto: any,
    algorithm: any,
    keyType: KeyType,
    keyUse: KeyUse,
    exportable: boolean = true): Promise<DidKey> {
    switch (keyType) {
      case KeyType.EC:
        return this.generateEcPairwiseKey(didMasterKey, crypto, algorithm, exportable);
      case KeyType.RSA:
        return this.generateRsaPairwiseKey(didMasterKey, crypto, algorithm, keyUse, exportable);
    }

    throw new Error(`Pairwise key for key type ${keyType} is not supported`);
  }

  /**
   * Generate a deterministic number that can be used as prime
   * @param crypto The crypto object.
   * @param keySize Desired key size
   * @param didMasterKey The DID master key
   * @param peerId The peer id
   */
  public async generateDeterministicNumberForPrime (crypto: any, primeSize: number, didMasterKey: Buffer, peerId: Buffer): Promise<Buffer> {
    const numberOfRounds: number = primeSize / (8 * 64);
    this._deterministicKey = Buffer.from('');
    const rounds: Array<(crypto: any, inx: number, key: Buffer, data: Buffer) => Promise<Buffer>> = [];
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
   * @param inx Round number
   * @param key Signature key
   * @param data Data to sign
   */
  private async generateHashForPrime (crypto: any, _inx: number, key: Buffer, data: Buffer): Promise<Buffer> {
    const alg = { name: 'hmac', hash: { name: 'SHA-512' } };
    const deterministicNumber = new DidKey(crypto, alg, key, true);
    await deterministicNumber.getJwkKey(KeyExport.Secret);
    const signature = await deterministicNumber.sign(data);
    this._deterministicKey = Buffer.concat([this._deterministicKey, Buffer.from(signature)]);
    return this._deterministicKey;
  }

  /**
   * Execute all rounds
   * @param rounds Array of functions to execute
   * @param inx Current step
   * @param key Key to sign
   * @param data Data to sign
   */
  private async executeRounds (crypto: any, rounds: Array<(crypto: any, inx: number, key: Buffer, data: Buffer) =>
    Promise<Buffer>>, inx: number, key: Buffer, data: Buffer): Promise<Buffer> {
    const signature: Buffer = await rounds[inx](crypto, inx, key, data);
    if (inx + 1 === rounds.length) {
      return this._deterministicKey;
    } else {
      await this.executeRounds(crypto, rounds, inx + 1, key, Buffer.from(signature));
      return this._deterministicKey;
    }
  }

  /**
   * Generate a prime number from the seed.
   * isProbablyPrime is based on the Miller-Rabin prime test.
   * @param primeSeed seed for prime generator
   */
  generatePrime (primeSeed: Array<number>): BigIntegerStatic {
    // make sure candidate is uneven, set high order bit
    primeSeed[primeSeed.length - 1] |= 0x1;
    primeSeed[0] |= 0x80;
    const two = bigInt(2);
    let prime = bigInt.fromArray(primeSeed, 256, false);
    this._numberOfPrimeTests = 1;
    while (true) {
      // 64 tests give 128 bit security
      if (prime.isProbablePrime(64)) {
        break;
      }
      prime = prime.add(two);
      this._numberOfPrimeTests++;
    }

    return prime;
  }

  /**
   * Generate the RSA pairwise Key.
   * @param didMasterKey The master key for this did.
   * @param crypto The crypto object.
   * @param algorithm Intended algorithm to use for the key.
   * @param keyUse Key usage.
   * @param exportable True if the key is exportable.
   */
  private async generateRsaPairwiseKey (
    didMasterKey: Buffer,
    crypto: any,
    algorithm: any,
    keyUse: KeyUse,
    exportable: boolean): Promise<DidKey> {

    // Set the ke\y size
    const keySize = algorithm.modulusLength || 1024;

    // Get peer id
    const peerId = Buffer.from(this._peerId);

    // Get deterministic base number for p
    const pBase: Buffer = await this.generateDeterministicNumberForPrime(crypto, keySize / 2, didMasterKey, peerId);

    // Get deterministic base number for q
    const qBase: Buffer = await this.generateDeterministicNumberForPrime(crypto, keySize / 2, pBase, peerId);
    const p = this.getPrime(pBase);
    const q = this.getPrime(qBase);

    // compute key components
    const modulus = p.multiply(q);
    const pMinus = p.subtract(bigInt.one);
    const qMinus = q.subtract(bigInt.one);
    const phi = pMinus.multiply(qMinus);
    const e = bigInt(65537);
    const d = e.modInv(phi);
    const dp = d.mod(pMinus);
    const dq = d.mod(qMinus);
    const qi = q.modInv(p);
    const jwk = {
      kty: 'RSA',
      use: keyUse.toString(),
      e: this.toBase(e),
      n: this.toBase(modulus),
      d: this.toBase(d),
      p: this.toBase(p),
      q: this.toBase(q),
      dp: this.toBase(dp),
      dq: this.toBase(dq),
      qi: this.toBase(qi)
    };

    return new DidKey(crypto, algorithm, jwk, exportable);
  }

  /**
   * Uses primeBase as reference and generate the closest prime number
   */
  private getPrime (primeBase: Buffer): any {
    const qArray = Array.from(primeBase);
    const prime: bigInt.BigIntegerStatic = this.generatePrime(qArray);
    return new bigInt(prime);
  }

  /**
   * Convert big number to base64 url.
   * @param bigNumber Number to convert
   */
  private toBase (bigNumber: any): string {
    let buf = Buffer.from(bigNumber.toArray(256).value);
    return base64url(buf);
  }

  /**
   * Generate the EC pairwise Key.
   * @param didMasterKey The master key for this did.
   * @param crypto The crypto object.
   * @param algorithm Intended algorithm to use for the key.
   * @param exportable True if the key is exportable.
   */
  private async generateEcPairwiseKey (
    didMasterKey: Buffer,
    crypto: any,
    algorithm: { namedCurve: string },
    exportable: boolean): Promise<DidKey> {

    // Generate peer key
    const alg = { name: 'hmac', hash: { name: 'SHA-256' } };
    const hashDidKey = new DidKey(crypto, alg, didMasterKey, true);
    const signature: any = await hashDidKey.sign(Buffer.from(this._peerId));

    if (SUPPORTED_CURVES.indexOf(algorithm.namedCurve) === -1) {
      throw new Error(`Curve ${algorithm.namedCurve} is not supported`);
    }

    const privateKey = new BN(Buffer.from(signature));
    const pair = secp256k1.keyPair({ priv: privateKey });
    const pubKey = pair.getPublic();
    const d = privateKey.toArrayLike(Buffer, 'be', 32);
    const x = pubKey.x.toArrayLike(Buffer, 'be', 32);
    const y = pubKey.y.toArrayLike(Buffer, 'be', 32);
    const jwk = {
      crv: algorithm.namedCurve,
      d: base64url.encode(d),
      x: base64url.encode(x),
      y: base64url.encode(y),
      kty: 'EC'
    };

    this._key = new DidKey(crypto, algorithm, jwk, exportable);
    return this._key;
  }
}
