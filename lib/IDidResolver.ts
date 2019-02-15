import IDidResolveResult from './IDidResolveResult';

/**
 * Interface for performing various DID lookup operations.
 *
 * @interface
 */
export default interface IDidResolver {

  /**
   * Gets a DID Document given a fully qualified DID
   * @param did A fully qualified DID
   * @return A {@link DidDocument} object
   */
  resolve (did: string): Promise<IDidResolveResult>;

}
