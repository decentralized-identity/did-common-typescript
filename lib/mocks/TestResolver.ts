import DidResolver, { ResolveResult } from '../DidResolver';
import DidDocument from '../DidDocument';

/**
 * A mock resolver designed to return whatever document you want
 */
export default class TestResolver implements DidResolver {
  /** Function called when requested */
  private handleRequest?: (did: string) => Promise<DidDocument>;

  async resolve (did: string): Promise<ResolveResult> {
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
