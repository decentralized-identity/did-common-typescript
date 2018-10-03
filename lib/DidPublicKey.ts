/**
 * Wrapper around a public key in the DID Document.
 * @interface
 */
export default interface DidPublicKey {
  /** Fully qualified public key id, such as did:example:123456789abcdefghi#keys-1 */
  id: string;
  /** Public Key Type */
  type: string;
  /** DID of the owner of the key */
  owner?: string;
}
