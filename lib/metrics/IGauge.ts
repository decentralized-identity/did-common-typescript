import IMetric from './IMetric';

/**
* Metric representing a fluctuating value, such as a rate.
*/
export default interface IGauge extends IMetric {
  /** Sample of the value */
  value: number;
}