import DidDocument from '../lib/DidDocument';
import IDidDocument from '../lib/IDidDocument';
import { IDidDocumentServiceDescriptor } from '../lib';

const did = 'did:example.me.id';
const baseDocument: IDidDocument = {
  '@context': 'https://w3id.org/did/v1',
  'id': did
};

/**
 * Helper to return a DID document with certain fields added/changed.
 */
const adjustBaseDocument = (fields: Partial<IDidDocument>) => {
  return new DidDocument(Object.assign({}, baseDocument, fields));
};

describe('DidDocument', () => {
  describe('getDidFromKeyId', () => {
    it('should return the correct DID from a correctly formatted key ID.', () => {
      const keyId = 'did:example:abc#key1';
      const did = DidDocument.getDidFromKeyId(keyId);
      expect(did).toEqual('did:example:abc');
    });
  });

  describe('constructor', () => {
    it(`should convert valid decentralized identifiers`, () => {
      const id = 'did:example:123456789abcdefghi';
      const json: IDidDocument = {
        '@context': 'https://w3id.org/did/v1',
        id,
        'publicKey': []
      };
      let document = new DidDocument(json);
      expect(document).toBeDefined();
      expect(document.id).toEqual(id);
    });

    it('should throw for missing ids', () => {
      const json = {
        '@context': 'https://w3id.org/did/v1',
        'publicKey': []
      };

      const throws = () => {
        console.log(new DidDocument(json as any));
      };

      expect(throws).toThrowError();
    });

    it('should throw for missing @context', () => {
      const id = 'did:example:123456789abcdefghi';
      const json = {
        id,
        publicKey: []
      };

      const throws = () => {
        console.log(new DidDocument(json as any));
      };

      expect(throws).toThrowError();
    });

    it('should allow missing publicKey', () => {
      const id = 'did:example:123456789abcdefghi';
      const json: IDidDocument = {
        '@context': 'https://w3id.org/did/v1',
        id
      };
      let document = new DidDocument(json);
      expect(document).toBeDefined();
      expect(document.id).toEqual(id);
    });

    it('should return public keys', () => {
      const id = 'did:example:123456789abcdefghi';
      const json: IDidDocument = {
        '@context': 'https://w3id.org/did/v1',
        id,
        'publicKey': [{
          id: `${id}#keys-1`,
          controller: id,
          type: 'test',
          publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n-----END PUBLIC KEY-----\r\n\r\n'
        },
          {
            id: `${id}#keys-2`,
            controller: id,
            type: 'test',
            publicKeyBase64: 'DEADBEEF'
          }]
      };

      const document = new DidDocument(json);

      expect(document).toBeDefined();
      expect(document.id).toEqual(id);
      expect(document.publicKey).toBeDefined();
      const keys = document.publicKey;
      if (!keys) {
        return;
      }
      expect(keys.length).toEqual(2);
      expect(keys[0].id).toEqual(`${id}#keys-1`);
      expect(keys[0].type).toEqual('test');
      expect((keys[0] as any)['publicKeyPem']).toBeDefined();
      expect(keys[1].id).toEqual(`${id}#keys-2`);
      expect(keys[1].controller).toBeDefined();
      expect(keys[1].controller).toEqual(id);
      expect(keys[1].type).toEqual('test');
      expect((keys[1] as any)['publicKeyBase64']).toBeDefined();
    });

    it('should ensure key IDs are fully-qualified', () => {
      const id = 'did:example:123456789abcdefghi';
      const json: IDidDocument = {
        '@context': 'https://w3id.org/did/v1',
        id,
        'publicKey': [
          {
            id: `key1`,
            controller: id,
            type: 'test',
            publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n-----END PUBLIC KEY-----\r\n\r\n'
          },
          {
            id: `#key2`,
            controller: id,
            type: 'test',
            publicKeyBase64: 'DEADBEEF'
          },
          {
            id: `${id}#key3`,
            controller: id,
            type: 'test',
            publicKeyBase64: 'DEADBEEF'
          }
        ]
      };

      let document = new DidDocument(json);
      expect(document.getPublicKey(`${id}#key1`)).toBeDefined();
      expect(document.getPublicKey(`${id}#key2`)).toBeDefined();
      expect(document.getPublicKey(`${id}#key3`)).toBeDefined();
      expect(document.getPublicKey(`${id}#key4`)).not.toBeDefined();
    });

  });

  describe('getPublicKey', () => {
    it('should retrieve the matching key', () => {
      const id = 'did:example:123456789abcdefghi';
      const json: IDidDocument = {
        '@context': 'https://w3id.org/did/v1',
        id,
        'publicKey': [{
          id: `${id}#keys-1`,
          controller: id,
          type: 'test',
          publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n-----END PUBLIC KEY-----\r\n\r\n'
        },
          {
            id: `${id}#keys-2`,
            type: 'test',
            controller: id,
            publicKeyBase64: 'DEADBEEF'
          }]
      };

      const document = new DidDocument(json);

      const publicKey = document.getPublicKey(`${id}#keys-1`);
      expect(publicKey).toBeDefined();
      if (!publicKey) {
        return;
      }
      expect(publicKey.type).toEqual('test');
    });

    it('should return undefined for no matching key', () => {
      const id = 'did:example:123456789abcdefghi';
      const json: IDidDocument = {
        '@context': 'https://w3id.org/did/v1',
        id,
        'publicKey': [{
          id: `${id}#keys-1`,
          type: 'test',
          controller: id,
          publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n-----END PUBLIC KEY-----\r\n\r\n'
        },
          {
            id: `${id}#keys-2`,
            type: 'test',
            controller: id,
            publicKeyBase64: 'DEADBEEF'
          }]
      };

      const document = new DidDocument(json);

      const publicKey = document.getPublicKey(`${id}#keys-3`);
      expect(publicKey).toBeUndefined();
    });

    it('should return undefined when no keys are defined', () => {
      const id = 'did:example:123456789abcdefghi';
      const json: IDidDocument = {
        '@context': 'https://w3id.org/did/v1',
        id
      };

      const document = new DidDocument(json);

      const publicKey = document.getPublicKey(`${id}#keys-1`);
      expect(publicKey).toBeUndefined();
    });
  });

  describe('getServices', () => {

    it('should return the services in the document', () => {
      const serviceJson: IDidDocumentServiceDescriptor[] = [{
        id: `${did};agent`,
        type: 'AgentService',
        serviceEndpoint: 'https://agent.example.com/837746'
      },
        {
          id: `${did};hub`,
          type: 'HubService',
          serviceEndpoint: 'https://hub.example.com'
        }];

      const document = adjustBaseDocument({
        service: serviceJson
      });

      expect(document.getServices()).toEqual(serviceJson);
    });

    it('should return an empty array if the service field is not present', () => {
      const document = new DidDocument(baseDocument);
      expect(Array.isArray(document.getServices())).toBeTruthy();
      expect(document.getServices()).toEqual([]);
    });

  });

  describe('getServicesByType', () => {

    it('should return services based on type', () => {
      const serviceJson: IDidDocumentServiceDescriptor[] = [{
        id: `${did};agent`,
        type: 'AgentService',
        serviceEndpoint: 'https://agent.example.com/837746'
      },
        {
          id: `${did};hub`,
          type: 'HubService',
          serviceEndpoint: 'https://hub.example.com'
        },
        {
          id: `${did};hub2`,
          type: 'HubService',
          serviceEndpoint: 'https://hub.example.com'
        }];

      const document = adjustBaseDocument({
        service: serviceJson
      });

      const services = document.getServicesByType('HubService');

      expect(services.length).toEqual(2);

      [0, 1].forEach((index) => {
        expect(services[index]).toEqual(serviceJson[index + 1]);
      });
    });

    it('should return an empty array if the service field is not present', () => {
      const document = new DidDocument(baseDocument);
      expect(Array.isArray(document.getServices())).toBeTruthy();
      expect(document.getServicesByType('foo')).toEqual([]);
    });

  });

});
