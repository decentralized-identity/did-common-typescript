/**
 * Class to model a master key
 */
class MasterKey {
  /**
   * Get the index for master key
   */
  did: string;

  /**
   * Get the master key
   */
  key: Buffer;

  /**
   * Create an instance of DidKey.
   * @param did The DID.
   * @param key The master key.
   */
  constructor (did: string, key: Buffer) {
    this.did = did;
    this.key = key;
  }
}
