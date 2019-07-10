import IMetric from './IMetric';

/**
* Metric representing a monotonically increasing value, such as a total.
*/
export default interface ICounter extends IMetric {
  /** Amount to increment on the counter */
  increment: number;
}