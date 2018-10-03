import DidDocument from './DidDocument';

/**
 * Interface for performing various DID lookup operations.
 * @interface
 */
export default interface DidResolver {
  /**
   * Gets a DID Document given a fully qualified DID
   * @param did A fully qualified DID
   * @return A {@link DidDocument} object
   */
  resolve (did: string): Promise<ResolveResult>;
}

/**
 * Returned results from a resolver
 * @interface
 */
export interface ResolveResult {
  /** The Did Document resolved for the given request */
  didDocument: DidDocument;
}
