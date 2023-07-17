import { CompilerOptions, Extension, ModuleSpecifierOptions, ModuleSpecifierResolutionHost, Path, SourceFile, Symbol, TypeChecker, UserPreferences } from "./_namespaces/ts";
/** @internal */
export declare function updateModuleSpecifier(compilerOptions: CompilerOptions, importingSourceFile: SourceFile, importingSourceFileName: Path, toFileName: string, host: ModuleSpecifierResolutionHost, oldImportSpecifier: string, options?: ModuleSpecifierOptions): string | undefined;
/** @internal */
export declare function getModuleSpecifier(compilerOptions: CompilerOptions, importingSourceFile: SourceFile, importingSourceFileName: Path, toFileName: string, host: ModuleSpecifierResolutionHost, options?: ModuleSpecifierOptions): string;
/** @internal */
export declare function getNodeModulesPackageName(compilerOptions: CompilerOptions, importingSourceFile: SourceFile, nodeModulesFileName: string, host: ModuleSpecifierResolutionHost, preferences: UserPreferences, options?: ModuleSpecifierOptions): string | undefined;
/** @internal */
export declare function tryGetModuleSpecifiersFromCache(moduleSymbol: Symbol, importingSourceFile: SourceFile, host: ModuleSpecifierResolutionHost, userPreferences: UserPreferences, options?: ModuleSpecifierOptions): readonly string[] | undefined;
/**
 * Returns an import for each symlink and for the realpath.
 *
 * @internal
 */
export declare function getModuleSpecifiers(moduleSymbol: Symbol, checker: TypeChecker, compilerOptions: CompilerOptions, importingSourceFile: SourceFile, host: ModuleSpecifierResolutionHost, userPreferences: UserPreferences, options?: ModuleSpecifierOptions): readonly string[];
/** @internal */
export declare function getModuleSpecifiersWithCacheInfo(moduleSymbol: Symbol, checker: TypeChecker, compilerOptions: CompilerOptions, importingSourceFile: SourceFile, host: ModuleSpecifierResolutionHost, userPreferences: UserPreferences, options?: ModuleSpecifierOptions): {
    moduleSpecifiers: readonly string[];
    computedWithoutCache: boolean;
};
/** @internal */
export declare function countPathComponents(path: string): number;
/** @internal */
export declare function forEachFileNameOfModule<T>(importingFileName: string, importedFileName: string, host: ModuleSpecifierResolutionHost, preferSymlinks: boolean, cb: (fileName: string, isRedirect: boolean) => T | undefined): T | undefined;
/** @internal */
export declare function tryGetRealFileNameForNonJsDeclarationFileName(fileName: string): string | undefined;
/** @internal */
export declare function tryGetJSExtensionForFile(fileName: string, options: CompilerOptions): Extension | undefined;
//# sourceMappingURL=moduleSpecifiers.d.ts.map