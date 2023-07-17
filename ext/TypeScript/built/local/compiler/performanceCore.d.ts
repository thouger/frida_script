/** @internal */
export interface PerformanceHooks {
    /** Indicates whether we should write native performance events */
    shouldWriteNativeEvents: boolean;
    performance: Performance;
    PerformanceObserver: PerformanceObserverConstructor;
}
/** @internal */
export interface Performance {
    mark(name: string): void;
    measure(name: string, startMark?: string, endMark?: string): void;
    clearMeasures(name?: string): void;
    clearMarks(name?: string): void;
    now(): number;
    timeOrigin: number;
}
/** @internal */
export interface PerformanceEntry {
    name: string;
    entryType: string;
    startTime: number;
    duration: number;
}
/** @internal */
export interface PerformanceObserverEntryList {
    getEntries(): PerformanceEntryList;
    getEntriesByName(name: string, type?: string): PerformanceEntryList;
    getEntriesByType(type: string): PerformanceEntryList;
}
/** @internal */
export interface PerformanceObserver {
    disconnect(): void;
    observe(options: {
        entryTypes: readonly ("mark" | "measure")[];
    }): void;
}
/** @internal */
export type PerformanceObserverConstructor = new (callback: (list: PerformanceObserverEntryList, observer: PerformanceObserver) => void) => PerformanceObserver;
/** @internal */
export type PerformanceEntryList = PerformanceEntry[];
/** @internal */
export declare function tryGetNativePerformanceHooks(): PerformanceHooks | undefined;
/**
 * Gets a timestamp with (at least) ms resolution
 *
 * @internal
 */
export declare const timestamp: () => number;
//# sourceMappingURL=performanceCore.d.ts.map