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

  /**
   * Times a codeBlock and emits a gauge metric
   * @param name Name of the gauge metric to emit
   * @param codeBlock Code to time, given a reference to the metric labels, and an optional stop function
   */
  static async time<T> (name: string, codeBlock: (labels: {[label: string]: any}, stop: () => void) => Promise<T>): Promise<T> {
    const startTimestamp = process.hrtime.bigint();
    let stopped = false;
    let labels: {[label: string]: any} = {};
    const stop = () => {
      const stopTimestamp = process.hrtime.bigint();
      if (!stopped) {
        stopped = true;
        Metrics.gauge({
          name,
          labels,
          value: parseFloat(((stopTimestamp - startTimestamp) / BigInt(1000000000)).toString(10))
        });
      }
    }
    const result = await codeBlock(labels, stop);
    stop();
    return result;
  }
}