/** @internal */
export interface PerfLogger {
    logEvent(msg: string): void;
    logErrEvent(msg: string): void;
    logPerfEvent(msg: string): void;
    logInfoEvent(msg: string): void;
    logStartCommand(command: string, msg: string): void;
    logStopCommand(command: string, msg: string): void;
    logStartUpdateProgram(msg: string): void;
    logStopUpdateProgram(msg: string): void;
    logStartUpdateGraph(): void;
    logStopUpdateGraph(): void;
    logStartResolveModule(name: string): void;
    logStopResolveModule(success: string): void;
    logStartParseSourceFile(filename: string): void;
    logStopParseSourceFile(): void;
    logStartReadFile(filename: string): void;
    logStopReadFile(): void;
    logStartBindFile(filename: string): void;
    logStopBindFile(): void;
    logStartScheduledOperation(operationId: string): void;
    logStopScheduledOperation(): void;
}
/**
 * Performance logger that will generate ETW events if possible - check for `logEvent` member, as `etwModule` will be `{}` when browserified
 *
 * @internal
 */
export declare const perfLogger: PerfLogger | undefined;
//# sourceMappingURL=perfLogger.d.ts.map