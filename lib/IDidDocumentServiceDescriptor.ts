/**
 * Defines a service descriptor entry present in a DID Document.
 */
export default interface IDidDocumentServiceDescriptor {

  /** The fully-qualified ID of this service, e.g. `did:example:me.id;agent`. */
  id: string;

  /** The type of this service. */
  type: string;

  /** The endpoint of this service, as a URI or JSON-LD object. */
  serviceEndpoint: string | object;

}
