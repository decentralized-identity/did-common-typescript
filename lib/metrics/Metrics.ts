import ICounter from "./ICounter";
import IGauge from "./IGauge";
import IMetricEmitter from "./IMetricEmitter";

/**
* Global Metrics class used to emit metrics
*/
export default class Metrics {
  /**
   * MetricEmitters to use when emitting metrics
   */
  static emitters: Set<IMetricEmitter> = new Set<IMetricEmitter>();
  
  /**
  * Emits a counter (monotonically increasing value)
  * @param counter The counter to emit
  */
  static count (counter: ICounter): void {
    this.emitters.forEach((emitter) => {
      emitter.emitCount(counter);
    });
  }
  
  /**
  * Emits a gauge (fluctuating value)
  * @param gauge The gauge to emit
  */
  static gauge (gauge: IGauge): void {
    this.emitters.forEach((emitter) => {
      emitter.emitGauge(gauge);
    });
  }
}