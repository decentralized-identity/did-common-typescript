import KeyTypeFactory, { KeyType } from '../../lib/crypto/KeyType';

describe('KeyType', () => {
  describe('Test KeyType factory', () => {
    it('Should return the correct key type.', () => {
      let alg = { name: 'hmac' };
      expect(KeyType.Oct).toBe(KeyTypeFactory.create(alg));
      alg = { name: 'ecdsa' };
      expect(KeyType.EC).toBe(KeyTypeFactory.create(alg));
      alg = { name: 'ecdh' };
      expect(KeyType.EC).toBe(KeyTypeFactory.create(alg));
      alg = { name: 'rsassa-pkcs1-v1_5' };
      expect(KeyType.RSA).toBe(KeyTypeFactory.create(alg));
    });

    it('Should throw.', () => {
      let alg = { name: 'xxx' };
      let throwDetected = false;
      try {
        KeyTypeFactory.create(alg);
      } catch (err) {
        throwDetected = true;
        expect(`The algorithm 'xxx' is not supported`).toBe(err.message);
      }

      if (!throwDetected) {
        fail('function should throw');
      }
    });
  });
});
