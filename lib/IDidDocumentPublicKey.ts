/**
 * Interface defining a public key definition entry in a DID Document.
 *
 * See: https://w3c-ccg.github.io/did-spec/#public-keys
 *
 * @interface
 */
export default interface IDidDocumentPublicKey {

  /** Fully qualified identifier of this public key, e.g. did:example:entity.id#keys-1 */
  id: string;

  /** The type of this public key, as defined in: https://w3c-ccg.github.io/ld-cryptosuite-registry/ */
  type: string;

  /** The DID of the controller of this key. */
  controller: string;

  /** The value of the public key in PEM format. Only one value field will be present. */
  publicKeyPem?: string;

  /** The value of the public key in JWK format. Only one value field will be present. */
  publicKeyJwk?: object;

  /** The value of the public key in hex format. Only one value field will be present. */
  publicKeyHex?: string;

  /** The value of the public key in Base64 format. Only one value field will be present. */
  publicKeyBase64?: string;

  /** The value of the public key in Base58 format. Only one value field will be present. */
  publicKeyBase58?: string;

  /** The value of the public key in Multibase format. Only one value field will be present. */
  publicKeyMultibase?: string;

}
