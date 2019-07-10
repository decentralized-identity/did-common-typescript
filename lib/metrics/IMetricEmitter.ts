import ICounter from './ICounter';
import IGauge from './IGauge';

/**
* MetricEmitter contract to be implemented by metric frameworks
*/
export default interface IMetricEmitter {
  /**
  * Emits a counter metric
  */
  emitCount: (counter: ICounter) => void;
  /**
  * Emits a gauge metric
  */
  emitGauge: (gauge: IGauge) => void;
}