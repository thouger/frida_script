import { CancellationToken, NavigateToItem, SourceFile, TypeChecker } from "./_namespaces/ts";
/** @internal */
export declare function getNavigateToItems(sourceFiles: readonly SourceFile[], checker: TypeChecker, cancellationToken: CancellationToken, searchValue: string, maxResultCount: number | undefined, excludeDtsFiles: boolean): NavigateToItem[];
//# sourceMappingURL=navigateTo.d.ts.map