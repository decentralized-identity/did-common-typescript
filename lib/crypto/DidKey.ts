import { KeyType } from './KeyType';
import { KeyUse } from './KeyUse';
import KeyObject from './KeyObject';
import PairwiseKey from './PairwiseKey';
import base64url from 'base64url';
import { Buffer } from 'buffer';

/**
 * Class to model a master key
 */
class MasterKey {
  /**
   * Get the index for master key
   */
  did: string;

  /**
   * Get the master key
   */
  key: Buffer;

  /**
   * Create an instance of DidKey.
   * @param did The DID.
   * @param key The master key.
   */
  constructor (did: string, key: Buffer) {
    this.did = did;
    this.key = key;
  }
}

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
  private _promise: Promise<any>;

  // Store jwk key. This is the format returned by exportKey
  private _jwkKey: any;

  // Store key object. This is the format returned by generateKey
  private _keyObject: any;

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
    this._promise = this.setKey(key);
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
  public get jwkKey (): Promise<any> {
    return this._promise.then((cryptoKey) => {
      if (!this._keyObject) {
        this._keyObject = new KeyObject(this.keyType, cryptoKey);
      }

      // Return the jwk key if exists
      if (this._jwkKey) {
        return this._jwkKey;
      }

      return this._crypto.subtle
        .exportKey('jwk', this.isKeyPair ? this._keyObject.privateKey : this._keyObject.secretKey)
        .then((jwkKey: any) => {
          return (this._jwkKey = jwkKey);
        }).catch((err: any) => {
          console.error(err);
          throw new Error(`DidKey:get jwkKey->Export key throwed ${err}`);
        });
    }).catch((err: any) => {
      console.error(err);
      throw new Error(`DidKey:get jwkKey->Returning object throwed ${err}`);
    });
  }

  /**
   * Sign the data with the current key
   * @param data  Data to be signed with the current key
   */
  public sign (data: Buffer): Promise<ArrayBuffer> {
    // console.log(`Sign data: ${base64url(data)}`);
    // console.log(`Sign key: ${this._jwkKey.k}`);

    let key = this.isKeyPair ? this._keyObject.privateKey : this._keyObject.secretKey;

    if (key) {
      return this._crypto.subtle.sign(this._algorithm, key, data).catch((err: any) => {
        console.error(err);
        throw new Error(`DidKey:sign->Signature failed ${err}`);
      });
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
  public verify (data: Buffer, signature: ArrayBuffer): Promise<boolean> {
    let key = this.isKeyPair ? this._keyObject.publicKey : this._keyObject.secretKey;

    if (key) {
      return this._crypto.subtle.verify(this._algorithm, key, signature, data).catch((err: any) => {
        console.error(err);
        throw new Error(`DidKey:verify->Verify failed ${err}`);
      });
    }

    if (this._keyObject.isPublicKeyCrypto) {
      throw new Error('The key has no public key for verifying');
    }

    throw new Error('No secret for verifying');
  }

  /**
   * Generate a pairwise key
   * @param seed  The master seed for generating pairwise keys
   * @param did  The owner DID
   * @param peerId  The representation of the peer
   */
  public generatePairwise (seed: Buffer, did: string, peerId: string): Promise<DidKey> {
    return this.generateDidMasterKey(seed, did). then((didMasterKey: MasterKey) => {
      let pairwise: DidKey | undefined = this._didPairwiseKeys.get(this.mapDidPairwiseKeys(peerId));
      if (pairwise) {
        return new Promise<DidKey>((resolve) => {
          resolve(pairwise);
        }).catch((err: any) => {
          console.error(err);
          throw new Error(`DidKey:generatePairwise->generatePairwise threw ${err}`);
        });
      }

      switch (this._keyType) {
        case KeyType.EC:
        case KeyType.RSA:

          // Generate new pairwise key
          const pairwiseKey: PairwiseKey = new PairwiseKey(did, peerId);
          return pairwiseKey.generate(didMasterKey.key, this._crypto, this._algorithm, this._keyType, this._keyUse, this._exportable)
          .then((pairwiseDidKey: DidKey) => {
            // Cache pairwise key
            this._didPairwiseKeys.set(this.mapDidPairwiseKeys(peerId), pairwiseDidKey);
            return pairwiseDidKey;
          }).catch((err: any) => {
            console.error(err);
            throw new Error(`DidKey:generatePairwise->generate threw ${err}`);
          });

        default:
          throw new Error(`Pairwise key for type '${this._keyType}' is not supported.`);
      }
    });
  }

  private mapDidPairwiseKeys (peerId: string): string {
    // TODO add key use if we want different keys for signing and encryption
    return `${this._keyType}_${peerId}`;
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
  private generateDidMasterKey (seed: Buffer, did: string): Promise<MasterKey> {
    let mk: MasterKey | undefined = undefined;

    // Check if key was already generated
    this._didMasterKeys.forEach((masterKey: MasterKey): any => {
      if (masterKey.did === did) {
        mk = masterKey;
        return;
      }
    });

    if (mk) {
      return new Promise((resolve) => {
        resolve(mk);
      });
    }

    let alg = { name: 'hmac', hash: 'SHA-512' };
    let signKey: DidKey = new DidKey(this._crypto, alg, KeyType.Oct, KeyUse.Signature, seed);
    return signKey.jwkKey.then(() => {
      return signKey.sign(Buffer.from(did)).then((signature: ArrayBuffer) => {
        mk = new MasterKey(did, Buffer.from(signature));
        this._didMasterKeys.push(mk);
        return mk;
      }).catch((err: any) => {
        console.error(err);
        throw new Error(`DidKey:generateDidMasterKey->sign threw ${err}`);
      });
    }).catch((err: any) => {
      console.error(err);
      throw new Error(`DidKey:generateDidMasterKey->get jwkKey threw ${err}`);
    });
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

  // Save the key or generate one if not specified by the caller
  private setKey (key: Buffer): Promise<any> {
    switch (this._keyType) {
      case KeyType.Oct:
        return this.setOctKey(key).catch((err: any) => {
          console.error(err);
          throw new Error(`DidKey:setKey->setOctKey threw ${err}`);
        });

      case KeyType.EC:
        return this.setEcKey(key).catch((err: any) => {
          console.error(err);
          throw new Error(`DidKey:setKey->setecKey threw ${err}`);
        });

      case KeyType.RSA:
        return this.setRsaKey(key).catch((err: any) => {
          console.error(err);
          throw new Error(`DidKey:setKey->setRsaKey threw ${err}`);
        });
    }

    throw new Error(`setKey: ${this._keyType} is not supported`);
  }

  // Save the oct key or generate one if not specified by the caller
  private setOctKey (key: Buffer): Promise<any> {
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
    return this._crypto.subtle.importKey('jwk', this._jwkKey, this._algorithm, this._exportable, this.setKeyUsage()).then((keyObject: any) => {
      this._keyObject = new KeyObject(this.keyType, keyObject);
    }).catch((err: any) => {
      console.error(err);
      throw new Error(`DidKey:setOctKey->importKey threw ${err}`);
    });
  }

  // Save the RSA key.
  private setRsaKey (jwkKey: any): Promise<any> {
    if (!jwkKey) {
      return this._crypto.subtle.generateKey(this._algorithm, this._exportable, this.setKeyUsage()).then((keyObject: any) => {
        this._keyObject = new KeyObject(this.keyType, keyObject);
      }).catch((err: any) => {
        console.error(err);
        throw new Error(`DidKey:setRsaKey->generateKey threw ${err}`);
      });
    }

    return this.setKeyPair(jwkKey).catch((err: any) => {
      console.error(err);
      throw new Error(`DidKey:setRsaKey->setKeyPair threw ${err}`);
    });
  }

  // Save the EC key or generate one if not specified by the caller
  private setEcKey (jwkKey: any): Promise<any> {
    if (!jwkKey) {
      return this._crypto.subtle.generateKey(this._algorithm, this._exportable, this.setKeyUsage()).then((keyObject: any) => {
        this._keyObject = new KeyObject(this.keyType, keyObject);
      }).catch((err: any) => {
        console.error(err);
        throw new Error(`DidKey:setEcKey->generateKey threw ${err}`);
      });
    }

    return this.setKeyPair(jwkKey).catch((err: any) => {
      console.error(err);
      throw new Error(`DidKey:setEcKey->setKeyPair threw ${err}`);
    });
  }

  private setKeyPair (jwkKey: any): Promise<any> {
    this._jwkKey = jwkKey;
    return this._crypto.subtle
      .importKey('jwk', jwkKey, this._algorithm, this._exportable, this.setKeyUsage())
      .then((keyObject: any) => {
        this._keyObject = new KeyObject(this.keyType, keyObject);
        if (this._keyObject.isPrivateKey) {
          // import the public key too
          return this._crypto.subtle.exportKey('jwk', this._keyObject.privateKey).then((jwk: any) => {
            if (this.keyType === KeyType.RSA) {
              // remove private key
              jwk.d = jwk.p = jwk.q = jwk.dp = jwk.dq = jwk.qi = undefined;
            } else {
              jwk.d = undefined;
            }

            return this._crypto.subtle
              .importKey('jwk', jwk, this._algorithm, this._exportable, this.setKeyUsage())
              .then((pubKeyObject: any) => {
                this._keyObject.publicKey = pubKeyObject;
                return this._jwkKey;
              }).catch((err: any) => {
                console.error(err);
                throw new Error(`DidKey:setKeyPair->second importKey threw ${err}`);
              });
          }).catch((err: any) => {
            console.error(err);
            throw new Error(`DidKey:setKeyPair->exportKey threw ${err}`);
          });
        }
      }).catch((err: any) => {
        console.error(err);
        throw new Error(`DidKey:setKeyPair->importKey threw ${err}`);
      });
  }
}
