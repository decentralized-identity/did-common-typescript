import DidDocument from '../lib/DidDocument';

describe('DidDocument', () => {
  describe('getDidFromKeyId', () => {
    it('should return the correct DID from a correctly formatted key ID.', () => {
      const keyId = 'did:example:abc#key1';
      const did = DidDocument.getDidFromKeyId(keyId);
      expect(did).toEqual('did:example:abc');
    });
  });

  describe('constructor', () => {
    it('should convert valid DIDs', () => {
      const id = 'did:example:123456789abcdefghi';
      const json = {
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
        console.log(new DidDocument(json));
      };

      expect(throws).toThrowError();
    });

    it('should thorw for missing @context', () => {
      const id = 'did:example:123456789abcdefghi';
      const json = {
        id,
        publicKey: []
      };

      const throws = () => {
        console.log(new DidDocument(json));
      };

      expect(throws).toThrowError();
    });

    it('should allow missing publicKey', () => {
      const id = 'did:example:123456789abcdefghi';
      const json = {
        '@context': 'https://w3id.org/did/v1',
        id
      };
      let document = new DidDocument(json);
      expect(document).toBeDefined();
      expect(document.id).toEqual(id);
    });

    it('should return public keys', () => {
      const id = 'did:example:123456789abcdefghi';
      const json = {
        '@context': 'https://w3id.org/did/v1',
        id,
        'publicKey': [{
          id: `${id}#keys-1`,
          type: 'test',
          publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n-----END PUBLIC KEY-----\r\n\r\n'
        },
          {
            id: `${id}#keys-2`,
            type: 'test',
            owner: id,
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
      expect(keys[1].owner).toBeDefined();
      expect(keys[1].owner).toEqual(id);
      expect(keys[1].type).toEqual('test');
      expect((keys[1] as any)['publicKeyBase64']).toBeDefined();
    });
  });

  describe('getPublicKey', () => {
    it('should retrieve the matching key', () => {
      const id = 'did:example:123456789abcdefghi';
      const json = {
        '@context': 'https://w3id.org/did/v1',
        id,
        'publicKey': [{
          id: `${id}#keys-1`,
          type: 'test',
          publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n-----END PUBLIC KEY-----\r\n\r\n'
        },
          {
            id: `${id}#keys-2`,
            type: 'test',
            owner: id,
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
      const json = {
        '@context': 'https://w3id.org/did/v1',
        id,
        'publicKey': [{
          id: `${id}#keys-1`,
          type: 'test',
          publicKeyPem: '-----BEGIN PUBLIC KEY-----\r\n-----END PUBLIC KEY-----\r\n\r\n'
        },
          {
            id: `${id}#keys-2`,
            type: 'test',
            owner: id,
            publicKeyBase64: 'DEADBEEF'
          }]
      };

      const document = new DidDocument(json);

      const publicKey = document.getPublicKey(`${id}#keys-3`);
      expect(publicKey).toBeUndefined();
    });

    it('should return undefined when no keys are defined', () => {
      const id = 'did:example:123456789abcdefghi';
      const json = {
        '@context': 'https://w3id.org/did/v1',
        id
      };

      const document = new DidDocument(json);

      const publicKey = document.getPublicKey(`${id}#keys-1`);
      expect(publicKey).toBeUndefined();
    });
  });
});
