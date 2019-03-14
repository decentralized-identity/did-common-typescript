/**
 * enum to model key export types
 */
export enum KeyExport {
  /**
   * The secret key
   */
  Secret = 'secret',

  /**
   * The private part of a key pair
   */
  Private = 'private',

  /**
   * The public part of a key pair
   */
  Public = 'public'
}
