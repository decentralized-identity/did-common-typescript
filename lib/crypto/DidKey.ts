import { KeyType } from './KeyType';
import { KeyUse } from './KeyUse';
import KeyObject from './KeyObject';
import base64url from 'base64url';
import { Buffer } from 'buffer';

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

  // Promise used to set the key
  private _promise: PromiseLike<any>;

  // Store jwk key. This is the format returned by exportKey
  private _jwkKey: any;

  // Store key object. This is the format returned by generateKey
  private _keyObject: any;

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
    key: Buffer | null = null,
    exportable: boolean = true
  ) {
    this._crypto = crypto;
    this._algorithm = algorithm;
    this._keyType = keyType;
    this._keyUse = keyUse;
    this._exportable = exportable;

    this._promise = this._setKey(key);
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
  public get jwkKey (): PromiseLike<any> {
    return this._promise.then((cryptoKey) => {
      if (!this._keyObject) {
        this._keyObject = new KeyObject(this.keyType, cryptoKey);
      }

      // Return the jwk key if exists
      if (this._jwkKey) {
        return this._jwkKey;
      }

      return this._crypto.subtle
        .exportKey('jwk', this._isKeyPair ? this._keyObject.privateKey : this._keyObject.secretKey)
        .then((jwkKey: any) => {
          return (this._jwkKey = jwkKey);
        });
    });
  }

  /**
   * Sign the data with the current key
   * @param data  Data to be signed with the current key
   */
  public sign (data: Buffer): PromiseLike<ArrayBuffer> {
    let key = this._isKeyPair ? this._keyObject.privateKey : this._keyObject.secretKey;

    if (key) {
      return this._crypto.subtle.sign(this._algorithm, key, data);
    }

    if (this._keyObject.isPublicKeyCrypto) {
      throw new Error('The key has no private key for signing');
    }

    throw new Error('No secret for signing');
  }

  /**
   * Sign the data with the current key
   * @param data  The data signed with the current key
   * @param signature  The signature on the data
   */
  public verify (data: Buffer, signature: ArrayBuffer): PromiseLike<boolean> {
    let key = this._isKeyPair ? this._keyObject.publicKey : this._keyObject.secretKey;

    if (key) {
      return this._crypto.subtle.verify(this._algorithm, key, signature, data);
    }

    if (this._keyObject.isPublicKeyCrypto) {
      throw new Error('The key has no public key for verifying');
    }

    throw new Error('No secret for verifying');
  }

  // True if the key is a key pair
  private get _isKeyPair (): boolean {
    return this._keyType === KeyType.EC || this._keyType === KeyType.RSA;
  }

  // Set keyUsage
  private _setKeyUsage (): string[] {
    switch (this._keyUse) {
      case KeyUse.Encryption:
        if (this._isKeyPair) {
          return [ 'deriveKey', 'deriveBits' ];
        }

        return [ 'encrypt', 'decrypt' ];

      case KeyUse.Signature:
        return [ 'sign', 'verify' ];
    }

    throw new Error(`The value for KeyUse '${this._keyUse}' is invalid. Needs to be sig or enc`);
  }

  // Save the key or generate one if not specified by the caller
  private _setKey (key: Buffer | null): PromiseLike<any> {
    switch (this._keyType) {
      case KeyType.Oct:
        return this._setOctKey(key);

      case KeyType.EC:
        return this._setEcKey(key);
    }

    throw new Error(`_setKey: ${this._keyType} is not supported`);
  }

  // Save the oct key or generate one if not specified by the caller
  private _setOctKey (key: Buffer | null): PromiseLike<any> {
    if (!key) {
      // Generate now random buffer
      let length = this._algorithm.length ? this._algorithm.length : 16;
      key = Buffer.alloc(length);
      key = this._crypto.getRandomValues(new Uint8Array(length));
    }

    // Set the JWK key
    let jwkKey = {};
    if (key) {
      jwkKey = {
        kty: 'oct',
        k: base64url.encode(key),
        use: this._keyUse
      };
    }

    this._jwkKey = jwkKey;
    return this._crypto.subtle
      .importKey('jwk', this._jwkKey, this._algorithm, this._exportable, this._setKeyUsage())
      .then((keyObject: any) => {
        this._keyObject = new KeyObject(this.keyType, keyObject);
        return this._keyObject;
      })
      .catch((err: Error) => {
        // Re-throw the error as a higher-level error.
        throw new Error(`import error for key type '${this._keyType}' - '${err.message}'.`);
      });
  }

  // Save the EC key or generate one if not specified by the caller
  private _setEcKey (jwkKey: any): PromiseLike<any> {
    if (!jwkKey) {
      return this._crypto.subtle.generateKey(this._algorithm, this._exportable, this._setKeyUsage()).then((keyObject: any) => {
        this._keyObject = new KeyObject(this.keyType, keyObject);
        return this._keyObject;
      });
    }

    this._jwkKey = jwkKey;
    return this._crypto.subtle
      .importKey('jwk', jwkKey, this._algorithm, this._exportable, this._setKeyUsage())
      .then((keyObject: any) => {
        this._keyObject = new KeyObject(this.keyType, keyObject);
        if (this._keyObject.isPrivateKey) {
          // import the public key too
          // this._crypto.subtle.exportKey('jwk')
          return this._crypto.subtle.exportKey('jwk', this._keyObject.privateKey).then((jwk: any) => {
            return this._crypto.subtle
              .importKey('jwk', jwk, this._algorithm, this._exportable, this._setKeyUsage())
              .then((pubKeyObject: any) => {
                keyObject.publicKey = pubKeyObject;
                return (this._keyObject = new KeyObject(this.keyType, keyObject));
              });
          });
        }
      });
  }
}
