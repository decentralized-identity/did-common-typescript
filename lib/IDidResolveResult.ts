import DidDocument from './DidDocument';

/**
 * Defines the type of a result returned by `IDidResolver#resolve()`.
 *
 * @interface
 */
export default interface IDidResolveResult {

  /** The DID Document resolved for the given request. */
  didDocument: DidDocument;

}
