import { CancellationToken, FileReference, Identifier, Node, Program, SourceFile, StringLiteral, StringLiteralLike, Symbol, TypeChecker } from "./_namespaces/ts";
/** @internal */
export interface ImportsResult {
    /** For every import of the symbol, the location and local symbol for the import. */
    importSearches: readonly [Identifier, Symbol][];
    /** For rename imports/exports `{ foo as bar }`, `foo` is not a local, so it may be added as a reference immediately without further searching. */
    singleReferences: readonly (Identifier | StringLiteral)[];
    /** List of source files that may (or may not) use the symbol via a namespace. (For UMD modules this is every file.) */
    indirectUsers: readonly SourceFile[];
}
/** @internal */
export type ImportTracker = (exportSymbol: Symbol, exportInfo: ExportInfo, isForRename: boolean) => ImportsResult;
/**
 * Creates the imports map and returns an ImportTracker that uses it. Call this lazily to avoid calling `getDirectImportsMap` unnecessarily.
 *
 * @internal
 */
export declare function createImportTracker(sourceFiles: readonly SourceFile[], sourceFilesSet: ReadonlySet<string>, checker: TypeChecker, cancellationToken: CancellationToken | undefined): ImportTracker;
/**
 * Info about an exported symbol to perform recursive search on.
 *
 * @internal
 */
export interface ExportInfo {
    exportingModuleSymbol: Symbol;
    exportKind: ExportKind;
}
/** @internal */
export declare const enum ExportKind {
    Named = 0,
    Default = 1,
    ExportEquals = 2
}
/** @internal */
export declare const enum ImportExport {
    Import = 0,
    Export = 1
}
/** @internal */
export type ModuleReference = 
/** "import" also includes require() calls. */
{
    kind: "import";
    literal: StringLiteralLike;
}
/** <reference path> or <reference types> */
 | {
    kind: "reference";
    referencingFile: SourceFile;
    ref: FileReference;
}
/** Containing file implicitly references the module (eg, via implicit jsx runtime import) */
 | {
    kind: "implicit";
    literal: StringLiteralLike;
    referencingFile: SourceFile;
};
/** @internal */
export declare function findModuleReferences(program: Program, sourceFiles: readonly SourceFile[], searchModuleSymbol: Symbol): ModuleReference[];
/** @internal */
export interface ImportedSymbol {
    kind: ImportExport.Import;
    symbol: Symbol;
}
/** @internal */
export interface ExportedSymbol {
    kind: ImportExport.Export;
    symbol: Symbol;
    exportInfo: ExportInfo;
}
/**
 * Given a local reference, we might notice that it's an import/export and recursively search for references of that.
 * If at an import, look locally for the symbol it imports.
 * If at an export, look for all imports of it.
 * This doesn't handle export specifiers; that is done in `getReferencesAtExportSpecifier`.
 * @param comingFromExport If we are doing a search for all exports, don't bother looking backwards for the imported symbol, since that's the reason we're here.
 *
 * @internal
 */
export declare function getImportOrExportSymbol(node: Node, symbol: Symbol, checker: TypeChecker, comingFromExport: boolean): ImportedSymbol | ExportedSymbol | undefined;
/** @internal */
export declare function getExportInfo(exportSymbol: Symbol, exportKind: ExportKind, checker: TypeChecker): ExportInfo | undefined;
//# sourceMappingURL=importTracker.d.ts.map