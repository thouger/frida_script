import { Path, Type } from "./_namespaces/ts";
/** @internal */
export declare let tracing: typeof tracingEnabled | undefined;
/**
 * Do not use this directly; instead @see {tracing}.
 * @internal
 */
export declare namespace tracingEnabled {
    type Mode = "project" | "build" | "server";
    interface Args {
        [key: string]: string | number | boolean | null | undefined | Args | readonly (string | number | boolean | null | undefined | Args)[];
    }
    /** Starts tracing for the given project. */
    export function startTracing(tracingMode: Mode, traceDir: string, configFilePath?: string): void;
    /** Stops tracing for the in-progress project and dumps the type catalog. */
    export function stopTracing(): void;
    export function recordType(type: Type): void;
    export const enum Phase {
        Parse = "parse",
        Program = "program",
        Bind = "bind",
        Check = "check",
        CheckTypes = "checkTypes",
        Emit = "emit",
        Session = "session"
    }
    export function instant(phase: Phase, name: string, args?: Args): void;
    /**
     * @param separateBeginAndEnd - used for special cases where we need the trace point even if the event
     * never terminates (typically for reducing a scenario too big to trace to one that can be completed).
     * In the future we might implement an exit handler to dump unfinished events which would deprecate
     * these operations.
     */
    export function push(phase: Phase, name: string, args?: Args, separateBeginAndEnd?: boolean): void;
    export function pop(results?: Args): void;
    export function popAll(): void;
    export function dumpLegend(): void;
    export {};
}
/** @internal */
export declare const startTracing: typeof tracingEnabled.startTracing;
/** @internal */
export declare const dumpTracingLegend: typeof tracingEnabled.dumpLegend;
/** @internal */
export interface TracingNode {
    tracingPath?: Path;
}
//# sourceMappingURL=tracing.d.ts.map