import { CompilerOptions, MapLike, Path, TypeAcquisition, Version } from "./_namespaces/ts";
export interface TypingResolutionHost {
    directoryExists(path: string): boolean;
    fileExists(fileName: string): boolean;
    readFile(path: string, encoding?: string): string | undefined;
    readDirectory(rootDir: string, extensions: readonly string[], excludes: readonly string[] | undefined, includes: readonly string[] | undefined, depth?: number): string[];
}
/** @internal */
export interface CachedTyping {
    typingLocation: string;
    version: Version;
}
/** @internal */
export declare function isTypingUpToDate(cachedTyping: CachedTyping, availableTypingVersions: MapLike<string>): boolean;
/** @internal */
export declare const prefixedNodeCoreModuleList: string[];
/** @internal */
export declare const nodeCoreModuleList: readonly string[];
/** @internal */
export declare const nodeCoreModules: Set<string>;
/** @internal */
export declare function nonRelativeModuleNameForTypingCache(moduleName: string): string;
/**
 * A map of loose file names to library names that we are confident require typings
 *
 * @internal
 */
export type SafeList = ReadonlyMap<string, string>;
/** @internal */
export declare function loadSafeList(host: TypingResolutionHost, safeListPath: Path): SafeList;
/** @internal */
export declare function loadTypesMap(host: TypingResolutionHost, typesMapPath: Path): SafeList | undefined;
/**
 * @param host is the object providing I/O related operations.
 * @param fileNames are the file names that belong to the same project
 * @param projectRootPath is the path to the project root directory
 * @param safeListPath is the path used to retrieve the safe list
 * @param packageNameToTypingLocation is the map of package names to their cached typing locations and installed versions
 * @param typeAcquisition is used to customize the typing acquisition process
 * @param compilerOptions are used as a source for typing inference
 *
 * @internal
 */
export declare function discoverTypings(host: TypingResolutionHost, log: ((message: string) => void) | undefined, fileNames: string[], projectRootPath: Path, safeList: SafeList, packageNameToTypingLocation: ReadonlyMap<string, CachedTyping>, typeAcquisition: TypeAcquisition, unresolvedImports: readonly string[], typesRegistry: ReadonlyMap<string, MapLike<string>>, compilerOptions: CompilerOptions): {
    cachedTypingPaths: string[];
    newTypingNames: string[];
    filesToWatch: string[];
};
/** @internal */
export declare const enum NameValidationResult {
    Ok = 0,
    EmptyName = 1,
    NameTooLong = 2,
    NameStartsWithDot = 3,
    NameStartsWithUnderscore = 4,
    NameContainsNonURISafeCharacters = 5
}
/** @internal */
export interface ScopedPackageNameValidationResult {
    name: string;
    isScopeName: boolean;
    result: NameValidationResult;
}
/** @internal */
export type PackageNameValidationResult = NameValidationResult | ScopedPackageNameValidationResult;
/**
 * Validates package name using rules defined at https://docs.npmjs.com/files/package.json
 *
 * @internal
 */
export declare function validatePackageName(packageName: string): PackageNameValidationResult;
/** @internal */
export declare function renderPackageNameValidationFailure(result: PackageNameValidationResult, typing: string): string;
//# sourceMappingURL=jsTyping.d.ts.map