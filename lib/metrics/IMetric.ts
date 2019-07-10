
/**
* Metric represents general metric parameters. IMetric should not be used directly.
*/
export default interface IMetric {
  /** Name of the metric */
  name: string;
  /** Labels for the metric sample */
  labels?: {[label: string]: any};
}