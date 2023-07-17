import { AnyImportOrRequireStatement, Comparer, Comparison, ExportDeclaration, Expression, FileTextChanges, formatting, ImportDeclaration, ImportOrExportSpecifier, ImportSpecifier, LanguageServiceHost, OrganizeImportsMode, Program, SortKind, SourceFile, UserPreferences } from "./_namespaces/ts";
/**
 * Organize imports by:
 *   1) Removing unused imports
 *   2) Coalescing imports from the same module
 *   3) Sorting imports
 *
 * @internal
 */
export declare function organizeImports(sourceFile: SourceFile, formatContext: formatting.FormatContext, host: LanguageServiceHost, program: Program, preferences: UserPreferences, mode: OrganizeImportsMode): FileTextChanges[];
/**
 * @param importGroup a list of ImportDeclarations, all with the same module name.
 *
 * @deprecated Only used for testing
 * @internal
 */
export declare function coalesceImports(importGroup: readonly ImportDeclaration[], ignoreCase: boolean, sourceFile?: SourceFile): readonly ImportDeclaration[];
/**
 * @param exportGroup a list of ExportDeclarations, all with the same module name.
 *
 * @deprecated Only used for testing
 * @internal
 */
export declare function coalesceExports(exportGroup: readonly ExportDeclaration[], ignoreCase: boolean): readonly ExportDeclaration[];
/** @internal */
export declare function compareImportOrExportSpecifiers<T extends ImportOrExportSpecifier>(s1: T, s2: T, comparer: Comparer<string>): Comparison;
/**
 * Exported for testing
 *
 * @deprecated Only used for testing
 * @internal
 */
export declare function compareModuleSpecifiers(m1: Expression | undefined, m2: Expression | undefined, ignoreCase?: boolean): Comparison;
/** @internal */
export declare function detectSorting(sourceFile: SourceFile, preferences: UserPreferences): SortKind;
/** @internal */
export declare function detectImportDeclarationSorting(imports: readonly AnyImportOrRequireStatement[], preferences: UserPreferences): SortKind;
/** @internal */
export declare const detectImportSpecifierSorting: (args_0: readonly ImportSpecifier[], args_1: UserPreferences) => SortKind;
/** @internal */
export declare function getImportDeclarationInsertionIndex(sortedImports: readonly AnyImportOrRequireStatement[], newImport: AnyImportOrRequireStatement, comparer: Comparer<string>): number;
/** @internal */
export declare function getImportSpecifierInsertionIndex(sortedImports: readonly ImportSpecifier[], newImport: ImportSpecifier, comparer: Comparer<string>): number;
/** @internal */
export declare function compareImportsOrRequireStatements(s1: AnyImportOrRequireStatement, s2: AnyImportOrRequireStatement, comparer: Comparer<string>): Comparison;
/** @internal */
export declare function getOrganizeImportsComparer(preferences: UserPreferences, ignoreCase: boolean): Comparer<string>;
//# sourceMappingURL=organizeImports.d.ts.map