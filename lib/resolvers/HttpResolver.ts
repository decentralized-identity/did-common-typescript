import IDidResolver from '../IDidResolver';
import IDidResolveResult from '../IDidResolveResult';
import DidDocument from '../DidDocument';

/** Options for constructing an HttpResolver. */
export interface HttpResolverOptions {

  /** The URL of the resolver service to use. */
  resolverUrl: string;

  /**
   * An implementation of the Fetch API to be used. This parameter is optional when used in a
   * browser environment; if not specified, the resolver will use `window.fetch`.
   *
   * Ideally this would be specified as type `GlobalFetch['fetch']`, however this would require all
   * consuming projects to include `dom` in their `tsconfig.lib` property, which is not desirable.
   */
  fetch?: any;

}

/**
 * Resolves DID Documents using a remote HTTP interface.
 */
export default class HttpResolver implements IDidResolver {

  private resolverUrl: string;

  private fetchImplementation: GlobalFetch['fetch'];

   /**
    * Constructs a new HTTP resolver.
    *
    * @param urlOrOptions The endpoint to query (as a string), or else an instance of `HttpResolverOptions`.
    */
  constructor (urlOrOptions: string | HttpResolverOptions) {
    if (typeof urlOrOptions === 'string') {
      this.resolverUrl = urlOrOptions;
      this.fetchImplementation = this.getDefaultFetchImplementation();
    } else {
      this.resolverUrl = urlOrOptions.resolverUrl;
      this.fetchImplementation = urlOrOptions.fetch || this.getDefaultFetchImplementation();
    }
  }

  private getDefaultFetchImplementation () {

    // tslint:disable-next-line
    if (typeof self === 'object' && 'fetch' in self) {
      return self.fetch.bind(self);
    }

    throw new Error('Please pass an implementation of fetch() to the HttpResolver.');
  }

  /**
   * Looks up a DID Document via HTTP.
   */
  public async resolve (did: string): Promise<IDidResolveResult> {
    const slash = this.resolverUrl.endsWith('/') ? '' : '/';
    const query = `${this.resolverUrl}${slash}1.0/identifiers/${did}`;
    const response = await this.fetchImplementation(query);

    if (!response.ok) {
      console.log(`Universal Resolver has returned ${response.status}`);

      switch (response.status) {
        case 404:
          throw new Error(`Decentralized ID Document not found for ${did}`);
        default:
          throw new Error(`Universal Resolver reported an error: ${response.statusText}`);
      }
    }

    const didDocument = await response.json();

    return {
      didDocument: new DidDocument(didDocument.document),
      metadata: didDocument.resolverMetadata
    } as IDidResolveResult;
  }
}
