import IMetricEmitter from "./IMetricEmitter";
import ICounter from "./ICounter";
import IGauge from "./IGauge";

/**
 * Metric Emitter to be used during testing
 */
export default class TestEmitter implements IMetricEmitter {

    emitCount(counter: ICounter) {
        console.info(`Counter: ${counter.name}`);
    }

    emitGauge(gauge: IGauge) {
        console.log(`Gauge: ${gauge.name}`)
    }
}