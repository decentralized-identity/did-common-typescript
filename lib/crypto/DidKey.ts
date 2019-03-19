import { KeyType } from './KeyType';
import { KeyUse } from './KeyUse';
import KeyObject from './KeyObject';
import PairwiseKey from './PairwiseKey';
import MasterKey from './MasterKey';
import base64url from 'base64url';
import { KeyExport } from './KeyExport';

/**
 * Class to model a key
 */
export default class DidKey {

  // key type
  private _keyType: KeyType;

  // key use
  private _keyUse: KeyUse;

  // algorithm to use
  private _algorithm: any;

  // the crypto object
  private _crypto: any;

  // Store symmetric key
  private _exportable: boolean;

  // Used to store the key passed by the caller
  private _rawKey: any;

 // Store for jwk keys in different formats. This is the format returned by exportKey
  private _jwkKeys: Map<string, object> = new Map<string, object>();

 // Store key objects. This is the format returned by generateKey
  private _keyObjects: Map<string, object> = new Map<string, object>();

  // Set of master keys
  private _didMasterKeys: MasterKey[] = [];

  // Set of pairwise keys
  private _didPairwiseKeys: Map<string, DidKey> = new Map<string, DidKey>();

  /**
   * Create an instance of DidKey.
   * @param crypto The crypto object.
   * @param algorithm Intended algorithm to use for the key.
   * @param keyType Key type.
   * @param keyUse Key usage.
   * @param key The key.
   * @param exportable True if the key is exportable.
   */
  public constructor (
    crypto: any,
    algorithm: any,
    keyType: KeyType,
    keyUse: KeyUse,
    key: any = undefined,
    exportable: boolean = true
  ) {
    this._crypto = crypto;
    this._keyType = keyType;
    this._keyUse = keyUse;
    this._exportable = exportable;

    // Check algorithm
    if (!algorithm.name) {
      throw new Error('Missing property name in algorithm');
    }

    switch (keyType) {
      case KeyType.EC:
        if (algorithm.name !== 'ECDSA' && algorithm.name !== 'ECDH') {
          throw new Error('For KeyType EC, property name in algorithm must be ECDSA or ECDH');
        }
        break;

      case KeyType.RSA:
        if (keyUse === KeyUse.Encryption) {
          if (algorithm.name !== 'RSA-OAEP') {
            throw new Error('For KeyType RSA encryption, property name in algorithm must be RSA-OAEP');
          }
        } else {
          if (algorithm.name !== 'RSASSA-PKCS1-v1_5') {
            throw new Error('For KeyType RSA signatures, property name in algorithm must be RSASSA-PKCS1-v1_5');
          }
        }
        break;
    }

    this._algorithm = this.normalizeAlgorithm(algorithm);

    // Set the raw key. Can be null if the key needs to be generated
    this._rawKey = key;
  }

  /**
   * Gets the key use.
   */
  public get keyUse (): KeyUse {
    return this._keyUse;
  }

  /**
   * Gets the key type.
   */
  public get keyType (): KeyType {
    return this._keyType;
  }

  /**
   * Gets the intended algorithm to use for the key.
   */
  public get algorithm (): any {
    return this._algorithm;
  }

  /**
   * Gets the exportable property of the key indicating whether the app can extract the key.
   */
  public get exportable (): boolean {
    return this._exportable;
  }

  /**
   * Gets the key in jwk format.
   */
  public async getJwkKey (keyExport: KeyExport): Promise<any> {
    // check if key is already cached
    let keyId = this.getKeyIdentifier(this.keyType, this.keyUse, keyExport);
    let jwkKey = this.getJwkKeyFromCache(keyId);
    if (jwkKey) {
      // Return the key if it already exists
      return jwkKey;
    }

    // Get the key or generate the key if needed
    let keyObject: KeyObject = await this.getOrGenerateKey();
    // Cache the key object
    this.cacheKeyObject(keyId, keyObject);
    // export to jwk format
    let jwk: any = await this.getJwkKeyFromKeyObject(keyExport, keyObject);

    // Save jwk format
    this.cacheJwkKey(keyId, jwk);

    // Check to save public key
    if (this.isKeyPair && keyExport === KeyExport.Private) {
      // Save only public key
      let jwkPublic: any = {};
      jwkPublic.kty = jwk.kty;
      jwkPublic.use = jwk.use;
      jwkPublic.key_ops = jwk.key_ops;
      if (this.keyType === KeyType.RSA) {
        jwkPublic.e = jwk.e;
        jwkPublic.n = jwk.n;
      } else {
        jwkPublic.crv = jwk.crv;
        jwkPublic.x = jwk.x;
        jwkPublic.y = jwk.y;
      }

      // Save public key
      let keyIdPublick = this.getKeyIdentifier(this.keyType, this.keyUse, KeyExport.Public);
      this.cacheJwkKey(keyIdPublick, jwkPublic);
      let keyObject: any = await this._crypto.subtle.importKey('jwk', jwkPublic, this._algorithm, this._exportable, this.setKeyUsage());
      this.cacheKeyObject(keyIdPublick, new KeyObject(this.keyType, keyObject));
    }
    return jwk;
  }

  /**
   * Sign the data with the current key
   * @param data  Data to be signed with the current key
   */
  public async sign (data: Buffer): Promise<ArrayBuffer> {
    let keyExport = this.isKeyPair ? KeyExport.Private : KeyExport.Secret;
    let keyId = this.getKeyIdentifier(this.keyType, this.keyUse, keyExport);
    // console.log(`Sign data: ${base64url(data)} with ${keyId}`);
    await this.getJwkKey(keyExport);
    let keyObject = this.getKeyObject(keyId);
    if (keyObject) {
      return this._crypto.subtle.sign(this._algorithm, this.isKeyPair ? (keyObject as any).privateKey : (keyObject as any).secretKey, data);
    } else {
      throw new Error(`No private key for signature: ${keyId}`);
    }
  }

  /**
   * Sign the data with the current key
   * @param data  The data signed with the current key
   * @param signature  The signature on the data
   */
  public async verify (data: Buffer, signature: ArrayBuffer): Promise<boolean> {
    // console.log(`Verify data: ${base64url(data)}`);
    let keyExport = this.isKeyPair ? KeyExport.Public : KeyExport.Secret;
    let jwk = await this.getJwkKey(keyExport);
    jwk.key_ops = ['verify'];
    let keyObject: any = await this._crypto.subtle.importKey('jwk', jwk, this._algorithm, this._exportable, this.setKeyUsage());
    return this._crypto.subtle.verify(this._algorithm, keyObject, signature, data);
  }

  /**
   * Generate a pairwise key
   * @param seed  The master seed for generating pairwise keys
   * @param did  The owner DID
   * @param peerId  The representation of the peer
   */
  public async generatePairwise (seed: Buffer, did: string, peerId: string): Promise<DidKey> {
    let pairwiseDidKey: DidKey;
    let didMasterKey: MasterKey = await this.generateDidMasterKey(seed, did);
    let pairwise: DidKey | undefined = this._didPairwiseKeys.get(this.mapDidPairwiseKeys(did, peerId));
    if (pairwise) {
      return pairwise;
    }

    switch (this._keyType) {
      case KeyType.EC:
      case KeyType.RSA:

        // Generate new pairwise key
        const pairwiseKey: PairwiseKey = new PairwiseKey(did, peerId);
        pairwiseDidKey = await pairwiseKey.generate(didMasterKey.key, this._crypto, this._algorithm, this._keyType, this._keyUse, this._exportable);

        // Cache pairwise key
        this._didPairwiseKeys.set(this.mapDidPairwiseKeys(did, peerId), pairwiseDidKey);
        break;

      default:
        throw new Error(`Pairwise key for type '${this._keyType}' is not supported.`);
    }
    // Store private and public key.
    await pairwiseDidKey.getJwkKey(KeyExport.Private);
    return pairwiseDidKey;
  }

  // Generate a unique key id for storage of pairwise keys
  private mapDidPairwiseKeys (did: string, peerId: string): string {
    // TODO add key use if we want different keys for signing and encryption
    return `${this._keyType}_${did}_${peerId}`;
  }

  // True if the key is a key pair
  private get isKeyPair (): boolean {
    return this._keyType === KeyType.EC || this._keyType === KeyType.RSA;
  }

  // Normalize the algorithm
  private normalizeAlgorithm (algorithm: any) {
    if (algorithm.namedCurve) {
      if (algorithm.namedCurve === 'P-256K') {
        algorithm.namedCurve = 'K-256';
      }
    }

    return algorithm;
  }

  /**
   * Generate a pairwise did master key.
   * @param seed  The master seed for generating pairwise keys
   * @param did  The owner DID
   * @param peerId  The representation of the peer
   */
  private async generateDidMasterKey (seed: Buffer, did: string): Promise<MasterKey> {
    let mk: MasterKey | undefined = undefined;

    // Check if key was already generated
    this._didMasterKeys.forEach((masterKey: MasterKey): any => {
      if (masterKey.did === did) {
        mk = masterKey;
        return;
      }
    });

    if (mk) {
      return mk;
    }

    let alg = { name: 'hmac', hash: 'SHA-512' };
    let signKey: DidKey = new DidKey(this._crypto, alg, KeyType.Oct, KeyUse.Signature, seed);
    await signKey.getJwkKey(KeyExport.Secret);
    let signature: ArrayBuffer = await signKey.sign(Buffer.from(did));
    mk = new MasterKey(did, Buffer.from(signature));
    this._didMasterKeys.push(mk);
    return mk;
  }

  // Set keyUsage
  private setKeyUsage (): string[] {
    switch (this._keyUse) {
      case KeyUse.Encryption:
        if (this.isKeyPair) {
          return [ 'deriveKey', 'deriveBits' ];
        }

        return [ 'encrypt', 'decrypt' ];

      case KeyUse.Signature:
        return [ 'sign', 'verify' ];
    }

    throw new Error(`The value for KeyUse '${this._keyUse}' is invalid. Needs to be sig or enc`);
  }

  // Transform the KeyObject into a JWK key
  private async getJwkKeyFromKeyObject (keyExport: KeyExport, keyObject: KeyObject): Promise<any> {
    if (!keyObject) {
      throw new Error('keyObject argument in getJwkKey cannot be null');
    }

    switch (this._keyType) {
      case KeyType.Oct:
        return this.getOctJwkKey(keyObject);

      case KeyType.RSA:
      case KeyType.EC:
        return this.getKeyPairJwkKey(keyExport, keyObject);
    }

    throw new Error(`DidKey:getJwkKey->${this._keyType} is not supported`);
  }

  // Transform the oct KeyObject into a JWK key.
  private async getOctJwkKey (keyObject: KeyObject): Promise<any> {
    let jwk: any = await this._crypto.subtle.exportKey('jwk', keyObject.secretKey);
    return jwk;
  }

  // Transform the key pair KeyObject into a JWK key.
  private async getKeyPairJwkKey (keyExport: KeyExport, keyObject: KeyObject): Promise<any> {
    let nativeKey = undefined;
    switch (keyExport) {
      case KeyExport.Private:
        nativeKey = keyObject.privateKey;
        break;
      case KeyExport.Public:
        nativeKey = keyObject.publicKey;
        break;
    }

    let jwk: any = await this._crypto.subtle.exportKey('jwk', nativeKey);
    return jwk;
  }

  private getKeyIdentifier (keyType: KeyType, keyUse: KeyUse, keyExport: KeyExport): string {
    return `${keyType}-${keyUse}-${keyExport}`;
  }

  private getJwkKeyFromCache (keyId: string): object | undefined {
    // TODO add decryption with a system key
    return this._jwkKeys.get(keyId);
  }

  private cacheJwkKey (keyId: string, jwk: object): boolean {
    // TODO add encryption with a system key
    this._jwkKeys.set(keyId, jwk);
    return true;
  }

  private getKeyObject (keyId: string): object | undefined {
    // TODO add decryption with a system key
    return this._keyObjects.get(keyId);
  }

  private cacheKeyObject (keyId: string, jwk: object): boolean {
    // TODO add encryption with a system key
    this._keyObjects.set(keyId, jwk);
    return true;
  }

  // Get the key or generate the key if needed
  // Return a keyObject
  private async getOrGenerateKey (): Promise<KeyObject> {
    if (this._rawKey === null) {
      // indicate key is generated and raw key was not set by caller
      this._rawKey = undefined;

      // key generation required
      switch (this.keyType) {
        case KeyType.EC:
        case KeyType.RSA:
          return this.generateKeyPair();
        case KeyType.Oct:
          return this.generateOctKey();
        default:
          throw new Error(`Key type '${this.keyType}' not supported`);
      }
    } else return this.setFromRawKey(this._rawKey);
  }

  // Generate KeyObject from raw key
  private async setFromRawKey (key: any): Promise<KeyObject> {
    if (!key) {
      throw new Error('Key must be defined');
    }

    let jwkKey = undefined;
    if (!key.kty) {
      jwkKey = {
        kty: 'oct',
        use: this.keyUse,
        k: base64url(key)
      };
    } else {
      jwkKey = key;
    }

    let keyObject: KeyObject = await this._crypto.subtle.importKey('jwk', jwkKey, this._algorithm, this._exportable, this.setKeyUsage());
    return new KeyObject(this.keyType, keyObject);
  }

  // Generate an oct key and return a key object
  private async generateOctKey (): Promise<KeyObject> {
    let keyObject: KeyObject = await this._crypto.subtle.generateKey(this._algorithm, this._exportable, this.setKeyUsage());
    return new KeyObject(this.keyType, keyObject);
  }

  // Generate a key pair and return a key object
  private async generateKeyPair (): Promise<KeyObject> {
    let keyObject: KeyObject = await this._crypto.subtle.generateKey(this._algorithm, this._exportable, this.setKeyUsage());
    return new KeyObject(this.keyType, keyObject);
  }
}
