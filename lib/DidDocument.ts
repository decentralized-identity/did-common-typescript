import DidPublicKey from './DidPublicKey';

/**
 * Class for performing various DID document operations.
 */
export default class DidDocument {

  /**
   * Returns the DID within the key ID given.
   * @param keyId A fully-qualified key ID. e.g. 'did:example:abc#key1'
   * @example 'did:example:abc#key1' returns 'did:example:abc'
   */
  public static getDidFromKeyId (keyId: string): string {
    const didLength = keyId.indexOf('#');
    const did = keyId.substr(0, didLength);
    return did;
  }

  /** Url of the @context for this document */
  public context: string;

  /** Id of the document (the DID) */
  public id: string;

  /** Array of public keys associated with the DID */
  public publicKey: DidPublicKey[];

  constructor (json: any) {
    for (let field of ['@context', 'id']) {
      if (!(field in json)) {
        throw new Error(`${field} is required`);
      }
    }
    this.context = json['@context'];
    this.id = json.id;
    this.publicKey = (json.publicKey || []);
  }

  /**
   * Gets the matching public key for a given key id
   * @param id fully qualified key id
   */
  public getPublicKey (id: string): DidPublicKey | undefined {
    return (this.publicKey || []).find(item => item.id === id);
  }
}
