/**
 * enum to model key use
 */
export enum KeyUse {
  Encryption = 'enc',
  Signature = 'sig'
}

/**
 * Factory class to create KeyUse objects
 */
export default class KeyUseFactory {
  /**
   * Create the key use according to the selected algortihm.
   * @param algorithm Web crypto compliant algorithm object
   */
  public static create (algorithm: any): KeyUse {
    switch (algorithm.name.toLowerCase()) {
      case 'hmac':
        return KeyUse.Signature;

      case 'ecdsa':
        return KeyUse.Signature;

      case 'ecdh':
        return KeyUse.Encryption;

      case 'rsassa-pkcs1-v1_5':
        return KeyUse.Signature;

      default:
        throw new Error(`The algorithm '${algorithm.name}' is not supported`);
    }
  }
}
