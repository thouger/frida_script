import { CancellationToken, CodeAction, CodeFixContextBase, CompilerOptions, DiagnosticWithLocation, ExportKind, formatting, Identifier, ImportKind, LanguageServiceHost, Program, ScriptTarget, SourceFile, Symbol, SymbolExportInfo, textChanges, UserPreferences } from "../_namespaces/ts";
/** @internal */
export declare const importFixName = "import";
/**
 * Computes multiple import additions to a file and writes them to a ChangeTracker.
 *
 * @internal
 */
export interface ImportAdder {
    hasFixes(): boolean;
    addImportFromDiagnostic: (diagnostic: DiagnosticWithLocation, context: CodeFixContextBase) => void;
    addImportFromExportedSymbol: (exportedSymbol: Symbol, isValidTypeOnlyUseSite?: boolean) => void;
    writeFixes: (changeTracker: textChanges.ChangeTracker) => void;
}
/** @internal */
export declare function createImportAdder(sourceFile: SourceFile, program: Program, preferences: UserPreferences, host: LanguageServiceHost, cancellationToken?: CancellationToken): ImportAdder;
/**
 * Computes module specifiers for multiple import additions to a file.
 *
 * @internal
 */
export interface ImportSpecifierResolver {
    getModuleSpecifierForBestExportInfo(exportInfo: readonly SymbolExportInfo[], position: number, isValidTypeOnlyUseSite: boolean, fromCacheOnly?: boolean): {
        exportInfo?: SymbolExportInfo;
        moduleSpecifier: string;
        computedWithoutCacheCount: number;
    } | undefined;
}
/** @internal */
export declare function createImportSpecifierResolver(importingFile: SourceFile, program: Program, host: LanguageServiceHost, preferences: UserPreferences): ImportSpecifierResolver;
/** @internal */
export declare function getImportCompletionAction(targetSymbol: Symbol, moduleSymbol: Symbol, exportMapKey: string | undefined, sourceFile: SourceFile, symbolName: string, isJsxTagName: boolean, host: LanguageServiceHost, program: Program, formatContext: formatting.FormatContext, position: number, preferences: UserPreferences, cancellationToken: CancellationToken): {
    readonly moduleSpecifier: string;
    readonly codeAction: CodeAction;
};
/** @internal */
export declare function getPromoteTypeOnlyCompletionAction(sourceFile: SourceFile, symbolToken: Identifier, program: Program, host: LanguageServiceHost, formatContext: formatting.FormatContext, preferences: UserPreferences): CodeAction | undefined;
/**
 * @param forceImportKeyword Indicates that the user has already typed `import`, so the result must start with `import`.
 * (In other words, do not allow `const x = require("...")` for JS files.)
 *
 * @internal
 */
export declare function getImportKind(importingFile: SourceFile, exportKind: ExportKind, compilerOptions: CompilerOptions, forceImportKeyword?: boolean): ImportKind;
/** @internal */
export declare function moduleSymbolToValidIdentifier(moduleSymbol: Symbol, target: ScriptTarget | undefined, forceCapitalize: boolean): string;
/** @internal */
export declare function moduleSpecifierToValidIdentifier(moduleSpecifier: string, target: ScriptTarget | undefined, forceCapitalize?: boolean): string;
//# sourceMappingURL=importFixes.d.ts.map