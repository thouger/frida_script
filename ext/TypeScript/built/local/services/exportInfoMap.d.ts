import { __String, CancellationToken, CompilerOptions, LanguageServiceHost, ModuleSpecifierCache, ModuleSpecifierResolutionHost, PackageJsonImportFilter, Path, Program, SourceFile, Symbol, SymbolFlags, TypeChecker, UserPreferences } from "./_namespaces/ts";
/** @internal */
export declare const enum ImportKind {
    Named = 0,
    Default = 1,
    Namespace = 2,
    CommonJS = 3
}
/** @internal */
export declare const enum ExportKind {
    Named = 0,
    Default = 1,
    ExportEquals = 2,
    UMD = 3
}
/** @internal */
export interface SymbolExportInfo {
    readonly symbol: Symbol;
    readonly moduleSymbol: Symbol;
    /** Set if `moduleSymbol` is an external module, not an ambient module */
    moduleFileName: string | undefined;
    exportKind: ExportKind;
    targetFlags: SymbolFlags;
    /** True if export was only found via the package.json AutoImportProvider (for telemetry). */
    isFromPackageJson: boolean;
}
/** @internal */
export interface ExportInfoMap {
    isUsableByFile(importingFile: Path): boolean;
    clear(): void;
    add(importingFile: Path, symbol: Symbol, key: __String, moduleSymbol: Symbol, moduleFile: SourceFile | undefined, exportKind: ExportKind, isFromPackageJson: boolean, checker: TypeChecker): void;
    get(importingFile: Path, key: string): readonly SymbolExportInfo[] | undefined;
    search<T>(importingFile: Path, preferCapitalized: boolean, matches: (name: string, targetFlags: SymbolFlags) => boolean, action: (info: readonly SymbolExportInfo[], symbolName: string, isFromAmbientModule: boolean, key: string) => T | undefined): T | undefined;
    releaseSymbols(): void;
    isEmpty(): boolean;
    /** @returns Whether the change resulted in the cache being cleared */
    onFileChanged(oldSourceFile: SourceFile, newSourceFile: SourceFile, typeAcquisitionEnabled: boolean): boolean;
}
/** @internal */
export interface CacheableExportInfoMapHost {
    getCurrentProgram(): Program | undefined;
    getPackageJsonAutoImportProvider(): Program | undefined;
    getGlobalTypingsCacheLocation(): string | undefined;
}
/** @internal */
export declare function createCacheableExportInfoMap(host: CacheableExportInfoMapHost): ExportInfoMap;
/** @internal */
export declare function isImportableFile(program: Program, from: SourceFile, to: SourceFile, preferences: UserPreferences, packageJsonFilter: PackageJsonImportFilter | undefined, moduleSpecifierResolutionHost: ModuleSpecifierResolutionHost, moduleSpecifierCache: ModuleSpecifierCache | undefined): boolean;
/** @internal */
export declare function forEachExternalModuleToImportFrom(program: Program, host: LanguageServiceHost, preferences: UserPreferences, useAutoImportProvider: boolean, cb: (module: Symbol, moduleFile: SourceFile | undefined, program: Program, isFromPackageJson: boolean) => void): void;
/** @internal */
export declare function getExportInfoMap(importingFile: SourceFile, host: LanguageServiceHost, program: Program, preferences: UserPreferences, cancellationToken: CancellationToken | undefined): ExportInfoMap;
/** @internal */
export declare function getDefaultLikeExportInfo(moduleSymbol: Symbol, checker: TypeChecker, compilerOptions: CompilerOptions): {
    resolvedSymbol: Symbol;
    name: string;
    symbol: Symbol;
    exportKind: ExportKind;
} | undefined;
/** @internal */
export declare function getDefaultExportInfoWorker(defaultExport: Symbol, checker: TypeChecker, compilerOptions: CompilerOptions): {
    readonly resolvedSymbol: Symbol;
    readonly name: string;
} | undefined;
//# sourceMappingURL=exportInfoMap.d.ts.map