/**
 * Returned by refactor functions when some error message needs to be surfaced to users.
 *
 * @internal
 */
export interface RefactorErrorInfo {
    error: string;
}
/**
 * Checks if some refactor info has refactor error info.
 *
 * @internal
 */
export declare function isRefactorErrorInfo(info: unknown): info is RefactorErrorInfo;
/**
 * Checks if string "known" begins with string "requested".
 * Used to match requested kinds with a known kind.
 *
 * @internal
 */
export declare function refactorKindBeginsWith(known: string, requested: string | undefined): boolean;
//# sourceMappingURL=helpers.d.ts.map