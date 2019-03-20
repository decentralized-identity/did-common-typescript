import KeyUseFactory, { KeyUse } from '../../lib/crypto/KeyUse';

describe('KeyUse', () => {
  describe('Test KeyUse factory', () => {
    it('Should return the correct key use.', () => {
      let alg = { name: 'hmac' };
      expect(KeyUse.Signature).toBe(KeyUseFactory.create(alg));
      alg = { name: 'ecdsa' };
      expect(KeyUse.Signature).toBe(KeyUseFactory.create(alg));
      alg = { name: 'ecdh' };
      expect(KeyUse.Encryption).toBe(KeyUseFactory.create(alg));
      alg = { name: 'rsassa-pkcs1-v1_5' };
      expect(KeyUse.Signature).toBe(KeyUseFactory.create(alg));
    });

    it('Should throw.', () => {
      let alg = { name: 'xxx' };
      let throwDetected = false;
      try {
        KeyUseFactory.create(alg);
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
