import { System } from "./_namespaces/ts";
/** @internal */
export interface Timer {
    enter(): void;
    exit(): void;
}
/** @internal */
export declare function createTimerIf(condition: boolean, measureName: string, startMarkName: string, endMarkName: string): Timer;
/** @internal */
export declare function createTimer(measureName: string, startMarkName: string, endMarkName: string): Timer;
/** @internal */
export declare const nullTimer: Timer;
/**
 * Marks a performance event.
 *
 * @param markName The name of the mark.
 *
 * @internal
 */
export declare function mark(markName: string): void;
/**
 * Adds a performance measurement with the specified name.
 *
 * @param measureName The name of the performance measurement.
 * @param startMarkName The name of the starting mark. If not supplied, the point at which the
 *      profiler was enabled is used.
 * @param endMarkName The name of the ending mark. If not supplied, the current timestamp is
 *      used.
 *
 * @internal
 */
export declare function measure(measureName: string, startMarkName?: string, endMarkName?: string): void;
/**
 * Gets the number of times a marker was encountered.
 *
 * @param markName The name of the mark.
 *
 * @internal
 */
export declare function getCount(markName: string): number;
/**
 * Gets the total duration of all measurements with the supplied name.
 *
 * @param measureName The name of the measure whose durations should be accumulated.
 *
 * @internal
 */
export declare function getDuration(measureName: string): number;
/**
 * Iterate over each measure, performing some action
 *
 * @param cb The action to perform for each measure
 *
 * @internal
 */
export declare function forEachMeasure(cb: (measureName: string, duration: number) => void): void;
/** @internal */
export declare function forEachMark(cb: (markName: string) => void): void;
/** @internal */
export declare function clearMeasures(name?: string): void;
/** @internal */
export declare function clearMarks(name?: string): void;
/**
 * Indicates whether the performance API is enabled.
 *
 * @internal
 */
export declare function isEnabled(): boolean;
/**
 * Enables (and resets) performance measurements for the compiler.
 *
 * @internal
 */
export declare function enable(system?: System): boolean;
/**
 * Disables performance measurements for the compiler.
 *
 * @internal
 */
export declare function disable(): void;
//# sourceMappingURL=performance.d.ts.map