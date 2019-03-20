import fetchMock from 'fetch-mock';
import HttpResolver from '../../lib/resolvers/HttpResolver';
import IDidDocument from '../../lib/IDidDocument';

const exampleUrl = 'http://example.com';
const exampleDid = 'did:test:example.id';
const exampleDocument: IDidDocument = {
  '@context': 'https://w3id.org/did/v1',
  'id': exampleDid
};

describe('HttpResolver', () => {

  describe('constructor', () => {

    it('should return use the default implementation when given a the correct DID from a correctly formatted key ID.', () => {
      (global as any).self = {
        fetch: () => 'testing'
      };

      const resolver = new HttpResolver(exampleUrl);
      expect(resolver['resolverUrl']).toEqual(exampleUrl);
      expect(resolver['fetchImplementation']).toBeDefined();
      expect(resolver['fetchImplementation']('https://example.com')).toEqual('testing' as any);

      delete (global as any).self;
    });

    it('should throw an error if no default implementation exists', () => {
      try {
        const resolver = new HttpResolver(exampleUrl);
        fail('Not expected to get here: ' + resolver);
      } catch (e) {
        expect(e.message).toContain('pass an implementation');
      }
    });

  });

  describe('resolve', () => {

    let resolver: HttpResolver;
    let mock: fetchMock.FetchMockSandbox;

    beforeEach(() => {
      mock = fetchMock.sandbox();
      resolver = new HttpResolver({
        resolverUrl: exampleUrl,
        fetch: mock
      });
    });

    it('should return a valid DID document.', async () => {
      mock.mock(`${exampleUrl}/1.0/identifiers/${exampleDid}`, JSON.stringify({
        document: exampleDocument,
        resolverMetadata: {}
      }));

      let response = await resolver.resolve(exampleDid);

      expect(response.didDocument.id).toEqual(exampleDid);
    });

    it('should throw an appropriate error for a 404 response.', async () => {
      mock.mock(`${exampleUrl}/1.0/identifiers/${exampleDid}`, 404);

      try {
        await resolver.resolve(exampleDid);
        fail('Should not reach here.');
      } catch (e) {
        expect(e.message).toContain('not found');
      }
    });

    it('should throw an appropriate error for a miscellaneous error response.', async () => {
      mock.mock(`${exampleUrl}/1.0/identifiers/${exampleDid}`, 500);

      try {
        await resolver.resolve(exampleDid);
        fail('Should not reach here.');
      } catch (e) {
        expect(e.message).toContain('reported an error');
      }
    });

  });

});
