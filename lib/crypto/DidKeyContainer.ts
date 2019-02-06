import DidKey from './DidKey';

/**
 * Class to model a key
 */
export default class DidKeyContainer {
  // list of keys
  private _keys: DidKey[] = [];

  /**
   * Gets the array of keys.
   */
  public get keys (): DidKey[] {
    return this._keys;
  }

  /**
   * Gets the the number of keys in the container.
   */
  public get count (): number {
    return this._keys.length;
  }

  /**
   * Add a key in the container.
   */
  public add (key: DidKey) {
    this._keys.push(key);
  }
}
