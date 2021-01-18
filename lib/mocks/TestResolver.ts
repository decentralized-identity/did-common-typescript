import IDidResolver from '../IDidResolver';
import IDidResolveResult from '../IDidResolveResult';
import DidDocument from '../DidDocument';

/**
 * A mock resolver designed to return whatever document you want
 */
export default class TestResolver implements IDidResolver {
  /** Function called when requested */
  private handleRequest?: (did: string) => Promise<DidDocument>;

  /**
   * Resolve a DID using the handleRequest function
   * @param did The DID to resolve
   */
  async resolve (did: string): Promise<IDidResolveResult> {
    if (!this.handleRequest) {
      throw new Error('TestResolver handler not set');
    }
    const document = await this.handleRequest(did);
    return {
      didDocument: document
    };
  }

  /** Calls handle whenever this resolver is requested to resolve a document. */
  setHandle (handle: (did: string) => Promise<DidDocument>) {
    this.handleRequest = handle;
  }

  /** resets the resolvers resolve function */
  resetHandle () {
    this.handleRequest = undefined;
  }
}
