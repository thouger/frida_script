import { CommandLineOption, CompilerOptions, DiagnosticMessage, DiagnosticReporter, GetEffectiveTypeRootsHost, MapLike, ModuleResolutionHost, ModuleResolutionKind, Path, ResolutionMode, ResolutionNameAndModeGetter, ResolvedModuleWithFailedLookupLocations, ResolvedProjectReference, ResolvedTypeReferenceDirectiveWithFailedLookupLocations, SourceFile } from "./_namespaces/ts";
/** @internal */
export declare function trace(host: ModuleResolutionHost, message: DiagnosticMessage, ...args: any[]): void;
/** @internal */
export declare function isTraceEnabled(compilerOptions: CompilerOptions, host: ModuleResolutionHost): boolean;
/** @internal */
export declare function updateResolutionField<T>(to: T[] | undefined, value: T[] | undefined): T[] | undefined;
/** @internal */
export interface ModuleResolutionState {
    host: ModuleResolutionHost;
    compilerOptions: CompilerOptions;
    traceEnabled: boolean;
    failedLookupLocations: string[] | undefined;
    affectingLocations: string[] | undefined;
    resultFromCache?: ResolvedModuleWithFailedLookupLocations;
    packageJsonInfoCache: PackageJsonInfoCache | undefined;
    features: NodeResolutionFeatures;
    conditions: readonly string[];
    requestContainingDirectory: string | undefined;
    reportDiagnostic: DiagnosticReporter;
    isConfigLookup: boolean;
    candidateIsFromPackageJsonField: boolean;
}
/** Just the fields that we use for module resolution.
 *
 * @internal
 */
export interface PackageJsonPathFields {
    typings?: string;
    types?: string;
    typesVersions?: MapLike<MapLike<string[]>>;
    main?: string;
    tsconfig?: string;
    type?: string;
    imports?: object;
    exports?: object;
    name?: string;
}
/** @internal */
export interface VersionPaths {
    version: string;
    paths: MapLike<string[]>;
}
/** @internal */
export declare function getPackageJsonTypesVersionsPaths(typesVersions: MapLike<MapLike<string[]>>): {
    version: string;
    paths: MapLike<string[]>;
} | undefined;
export declare function getEffectiveTypeRoots(options: CompilerOptions, host: GetEffectiveTypeRootsHost): string[] | undefined;
/**
 * @param {string | undefined} containingFile - file that contains type reference directive, can be undefined if containing file is unknown.
 * This is possible in case if resolution is performed for directives specified via 'types' parameter. In this case initial path for secondary lookups
 * is assumed to be the same as root directory of the project.
 */
export declare function resolveTypeReferenceDirective(typeReferenceDirectiveName: string, containingFile: string | undefined, options: CompilerOptions, host: ModuleResolutionHost, redirectedReference?: ResolvedProjectReference, cache?: TypeReferenceDirectiveResolutionCache, resolutionMode?: ResolutionMode): ResolvedTypeReferenceDirectiveWithFailedLookupLocations;
/** @internal */
export declare function getConditions(options: CompilerOptions, esmMode?: boolean): string[];
/**
 * @internal
 * Does not try `@types/${packageName}` - use a second pass if needed.
 */
export declare function resolvePackageNameToPackageJson(packageName: string, containingDirectory: string, options: CompilerOptions, host: ModuleResolutionHost, cache: ModuleResolutionCache | undefined): PackageJsonInfo | undefined;
/**
 * Given a set of options, returns the set of type directive names
 *   that should be included for this program automatically.
 * This list could either come from the config file,
 *   or from enumerating the types root + initial secondary types lookup location.
 * More type directives might appear in the program later as a result of loading actual source files;
 *   this list is only the set of defaults that are implicitly included.
 */
export declare function getAutomaticTypeDirectiveNames(options: CompilerOptions, host: ModuleResolutionHost): string[];
export interface TypeReferenceDirectiveResolutionCache extends PerDirectoryResolutionCache<ResolvedTypeReferenceDirectiveWithFailedLookupLocations>, NonRelativeNameResolutionCache<ResolvedTypeReferenceDirectiveWithFailedLookupLocations>, PackageJsonInfoCache {
    /** @internal */ clearAllExceptPackageJsonInfoCache(): void;
}
export interface ModeAwareCache<T> {
    get(key: string, mode: ResolutionMode): T | undefined;
    set(key: string, mode: ResolutionMode, value: T): this;
    delete(key: string, mode: ResolutionMode): this;
    has(key: string, mode: ResolutionMode): boolean;
    forEach(cb: (elem: T, key: string, mode: ResolutionMode) => void): void;
    size(): number;
}
/**
 * Cached resolutions per containing directory.
 * This assumes that any module id will have the same resolution for sibling files located in the same folder.
 */
export interface PerDirectoryResolutionCache<T> {
    getFromDirectoryCache(name: string, mode: ResolutionMode, directoryName: string, redirectedReference: ResolvedProjectReference | undefined): T | undefined;
    getOrCreateCacheForDirectory(directoryName: string, redirectedReference?: ResolvedProjectReference): ModeAwareCache<T>;
    clear(): void;
    /**
     *  Updates with the current compilerOptions the cache will operate with.
     *  This updates the redirects map as well if needed so module resolutions are cached if they can across the projects
     */
    update(options: CompilerOptions): void;
}
export interface NonRelativeNameResolutionCache<T> {
    getFromNonRelativeNameCache(nonRelativeName: string, mode: ResolutionMode, directoryName: string, redirectedReference: ResolvedProjectReference | undefined): T | undefined;
    getOrCreateCacheForNonRelativeName(nonRelativeName: string, mode: ResolutionMode, redirectedReference?: ResolvedProjectReference): PerNonRelativeNameCache<T>;
    clear(): void;
    /**
     *  Updates with the current compilerOptions the cache will operate with.
     *  This updates the redirects map as well if needed so module resolutions are cached if they can across the projects
     */
    update(options: CompilerOptions): void;
}
export interface PerNonRelativeNameCache<T> {
    get(directory: string): T | undefined;
    set(directory: string, result: T): void;
}
export interface ModuleResolutionCache extends PerDirectoryResolutionCache<ResolvedModuleWithFailedLookupLocations>, NonRelativeModuleNameResolutionCache, PackageJsonInfoCache {
    getPackageJsonInfoCache(): PackageJsonInfoCache;
    /** @internal */ clearAllExceptPackageJsonInfoCache(): void;
}
/**
 * Stored map from non-relative module name to a table: directory -> result of module lookup in this directory
 * We support only non-relative module names because resolution of relative module names is usually more deterministic and thus less expensive.
 */
export interface NonRelativeModuleNameResolutionCache extends NonRelativeNameResolutionCache<ResolvedModuleWithFailedLookupLocations>, PackageJsonInfoCache {
    /** @deprecated Use getOrCreateCacheForNonRelativeName */
    getOrCreateCacheForModuleName(nonRelativeModuleName: string, mode: ResolutionMode, redirectedReference?: ResolvedProjectReference): PerModuleNameCache;
}
export interface PackageJsonInfoCache {
    /** @internal */ getPackageJsonInfo(packageJsonPath: string): PackageJsonInfo | boolean | undefined;
    /** @internal */ setPackageJsonInfo(packageJsonPath: string, info: PackageJsonInfo | boolean): void;
    /** @internal */ entries(): [Path, PackageJsonInfo | boolean][];
    /** @internal */ getInternalMap(): Map<Path, PackageJsonInfo | boolean> | undefined;
    clear(): void;
}
export type PerModuleNameCache = PerNonRelativeNameCache<ResolvedModuleWithFailedLookupLocations>;
/** @internal */
export declare function getKeyForCompilerOptions(options: CompilerOptions, affectingOptionDeclarations: readonly CommandLineOption[]): string;
/** @internal */
export interface CacheWithRedirects<K, V> {
    getMapOfCacheRedirects(redirectedReference: ResolvedProjectReference | undefined): Map<K, V> | undefined;
    getOrCreateMapOfCacheRedirects(redirectedReference: ResolvedProjectReference | undefined): Map<K, V>;
    update(newOptions: CompilerOptions): void;
    clear(): void;
}
/** @internal */
export declare function createCacheWithRedirects<K, V>(ownOptions: CompilerOptions | undefined): CacheWithRedirects<K, V>;
/** @internal */
export type ModeAwareCacheKey = string & {
    __modeAwareCacheKey: any;
};
/** @internal */
export declare function createModeAwareCacheKey(specifier: string, mode: ResolutionMode): ModeAwareCacheKey;
/** @internal */
export declare function createModeAwareCache<T>(): ModeAwareCache<T>;
/** @internal */
export declare function zipToModeAwareCache<K, V>(file: SourceFile, keys: readonly K[], values: readonly V[], nameAndModeGetter: ResolutionNameAndModeGetter<K, SourceFile>): ModeAwareCache<V>;
export declare function createModuleResolutionCache(currentDirectory: string, getCanonicalFileName: (s: string) => string, options?: CompilerOptions, packageJsonInfoCache?: PackageJsonInfoCache): ModuleResolutionCache;
export declare function createTypeReferenceDirectiveResolutionCache(currentDirectory: string, getCanonicalFileName: (s: string) => string, options?: CompilerOptions, packageJsonInfoCache?: PackageJsonInfoCache): TypeReferenceDirectiveResolutionCache;
/** @internal */
export declare function getOptionsForLibraryResolution(options: CompilerOptions): {
    moduleResolution: ModuleResolutionKind;
    traceResolution: boolean | undefined;
};
/** @internal */
export declare function resolveLibrary(libraryName: string, resolveFrom: string, compilerOptions: CompilerOptions, host: ModuleResolutionHost, cache?: ModuleResolutionCache): ResolvedModuleWithFailedLookupLocations;
export declare function resolveModuleNameFromCache(moduleName: string, containingFile: string, cache: ModuleResolutionCache, mode?: ResolutionMode): ResolvedModuleWithFailedLookupLocations | undefined;
export declare function resolveModuleName(moduleName: string, containingFile: string, compilerOptions: CompilerOptions, host: ModuleResolutionHost, cache?: ModuleResolutionCache, redirectedReference?: ResolvedProjectReference, resolutionMode?: ResolutionMode): ResolvedModuleWithFailedLookupLocations;
/**
 * Expose resolution logic to allow us to use Node module resolution logic from arbitrary locations.
 * No way to do this with `require()`: https://github.com/nodejs/node/issues/5963
 * Throws an error if the module can't be resolved.
 *
 * @internal
 */
export declare function resolveJSModule(moduleName: string, initialDir: string, host: ModuleResolutionHost): string;
/** @internal */
export declare enum NodeResolutionFeatures {
    None = 0,
    Imports = 2,
    SelfName = 4,
    Exports = 8,
    ExportsPatternTrailers = 16,
    AllFeatures = 30,
    Node16Default = 30,
    NodeNextDefault = 30,
    BundlerDefault = 30,
    EsmMode = 32
}
export declare function bundlerModuleNameResolver(moduleName: string, containingFile: string, compilerOptions: CompilerOptions, host: ModuleResolutionHost, cache?: ModuleResolutionCache, redirectedReference?: ResolvedProjectReference): ResolvedModuleWithFailedLookupLocations;
export declare function nodeModuleNameResolver(moduleName: string, containingFile: string, compilerOptions: CompilerOptions, host: ModuleResolutionHost, cache?: ModuleResolutionCache, redirectedReference?: ResolvedProjectReference): ResolvedModuleWithFailedLookupLocations;
/** @internal */ export declare function nodeModuleNameResolver(moduleName: string, containingFile: string, compilerOptions: CompilerOptions, host: ModuleResolutionHost, cache?: ModuleResolutionCache, redirectedReference?: ResolvedProjectReference, lookupConfig?: boolean): ResolvedModuleWithFailedLookupLocations;
/** @internal */
export declare function nodeNextJsonConfigResolver(moduleName: string, containingFile: string, host: ModuleResolutionHost): ResolvedModuleWithFailedLookupLocations;
/** @internal */
export declare const nodeModulesPathPart = "/node_modules/";
/** @internal */
export declare function pathContainsNodeModules(path: string): boolean;
/**
 * This will be called on the successfully resolved path from `loadModuleFromFile`.
 * (Not needed for `loadModuleFromNodeModules` as that looks up the `package.json` as part of resolution.)
 *
 * packageDirectory is the directory of the package itself.
 *   For `blah/node_modules/foo/index.d.ts` this is packageDirectory: "foo"
 *   For `/node_modules/foo/bar.d.ts` this is packageDirectory: "foo"
 *   For `/node_modules/@types/foo/bar/index.d.ts` this is packageDirectory: "@types/foo"
 *   For `/node_modules/foo/bar/index.d.ts` this is packageDirectory: "foo"
 *
 * @internal
 */
export declare function parseNodeModuleFromPath(resolved: string, isFolder?: boolean): string | undefined;
/** @internal */
export declare function getEntrypointsFromPackageJsonInfo(packageJsonInfo: PackageJsonInfo, options: CompilerOptions, host: ModuleResolutionHost, cache: ModuleResolutionCache | undefined, resolveJs?: boolean): string[] | false;
/** @internal */
export declare function getTemporaryModuleResolutionState(packageJsonInfoCache: PackageJsonInfoCache | undefined, host: ModuleResolutionHost, options: CompilerOptions): ModuleResolutionState;
/** @internal */
export interface PackageJsonInfo {
    packageDirectory: string;
    contents: PackageJsonInfoContents;
}
/** @internal */
export interface PackageJsonInfoContents {
    packageJsonContent: PackageJsonPathFields;
    /** false: versionPaths are not present. undefined: not yet resolved */
    versionPaths: VersionPaths | false | undefined;
    /** false: resolved to nothing. undefined: not yet resolved */
    resolvedEntrypoints: string[] | false | undefined;
}
/**
 * A function for locating the package.json scope for a given path
 *
 * @internal
 */
export declare function getPackageScopeForPath(fileName: string, state: ModuleResolutionState): PackageJsonInfo | undefined;
/** @internal */
export declare function getPackageJsonInfo(packageDirectory: string, onlyRecordFailures: boolean, state: ModuleResolutionState): PackageJsonInfo | undefined;
/** @internal */
export declare function parsePackageName(moduleName: string): {
    packageName: string;
    rest: string;
};
/** @internal */
export declare function allKeysStartWithDot(obj: MapLike<unknown>): boolean;
/**
 * @internal
 * From https://github.com/nodejs/node/blob/8f39f51cbbd3b2de14b9ee896e26421cc5b20121/lib/internal/modules/esm/resolve.js#L722 -
 * "longest" has some nuance as to what "longest" means in the presence of pattern trailers
 */
export declare function comparePatternKeys(a: string, b: string): 1 | -1 | 0;
/** @internal */
export declare function isApplicableVersionedTypesKey(conditions: readonly string[], key: string): boolean;
/** @internal */
export declare function getTypesPackageName(packageName: string): string;
/** @internal */
export declare function mangleScopedPackageName(packageName: string): string;
/** @internal */
export declare function getPackageNameFromTypesPackageName(mangledName: string): string;
/** @internal */
export declare function unmangleScopedPackageName(typesPackageName: string): string;
export declare function classicNameResolver(moduleName: string, containingFile: string, compilerOptions: CompilerOptions, host: ModuleResolutionHost, cache?: NonRelativeModuleNameResolutionCache, redirectedReference?: ResolvedProjectReference): ResolvedModuleWithFailedLookupLocations;
/** @internal */
export declare function shouldAllowImportingTsExtension(compilerOptions: CompilerOptions, fromFileName?: string): boolean | "" | undefined;
/**
 * A host may load a module from a global cache of typings.
 * This is the minumum code needed to expose that functionality; the rest is in the host.
 *
 * @internal
 */
export declare function loadModuleFromGlobalCache(moduleName: string, projectName: string | undefined, compilerOptions: CompilerOptions, host: ModuleResolutionHost, globalCache: string, packageJsonInfoCache: PackageJsonInfoCache): ResolvedModuleWithFailedLookupLocations;
//# sourceMappingURL=moduleNameResolver.d.ts.map