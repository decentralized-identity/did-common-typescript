import IDidDocumentServiceDescriptor from './IDidDocumentServiceDescriptor';
import IDidDocumentPublicKey from './IDidDocumentPublicKey';

/**
 * Interface describing the expected shape of a Decentralized Identity Document.
 */
export default interface IDidDocument {

  /** The standard context for DID Documents. */
  '@context': 'https://w3id.org/did/v1';

  /** The DID to which this DID Document pertains. */
  id: string;

  /** Array of public keys associated with the DID. */
  publicKey?: IDidDocumentPublicKey[];

  /** Array of services associated with the DID. */
  service?: IDidDocumentServiceDescriptor[];

  /** Array of authentication methods. */
  authentication?: (string | object)[];

}
