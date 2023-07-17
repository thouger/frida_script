import { BuilderProgram, CompilerOptions, DirectoryWatcherCallback, ExtendedConfigCacheEntry, FileExtensionInfo, FileWatcher, FileWatcherCallback, FileWatcherEventKind, Path, PollingInterval, Program, WatchDirectoryFlags, WatchOptions } from "./_namespaces/ts";
/**
 * Partial interface of the System thats needed to support the caching of directory structure
 *
 * @internal
 */
export interface DirectoryStructureHost {
    fileExists(path: string): boolean;
    readFile(path: string, encoding?: string): string | undefined;
    directoryExists?(path: string): boolean;
    getDirectories?(path: string): string[];
    readDirectory?(path: string, extensions?: readonly string[], exclude?: readonly string[], include?: readonly string[], depth?: number): string[];
    realpath?(path: string): string;
    createDirectory?(path: string): void;
    writeFile?(path: string, data: string, writeByteOrderMark?: boolean): void;
}
/** @internal */
export interface FileAndDirectoryExistence {
    fileExists: boolean;
    directoryExists: boolean;
}
/** @internal */
export interface CachedDirectoryStructureHost extends DirectoryStructureHost {
    useCaseSensitiveFileNames: boolean;
    getDirectories(path: string): string[];
    readDirectory(path: string, extensions?: readonly string[], exclude?: readonly string[], include?: readonly string[], depth?: number): string[];
    /** Returns the queried result for the file exists and directory exists if at all it was done */
    addOrDeleteFileOrDirectory(fileOrDirectory: string, fileOrDirectoryPath: Path): FileAndDirectoryExistence | undefined;
    addOrDeleteFile(fileName: string, filePath: Path, eventKind: FileWatcherEventKind): void;
    clearCache(): void;
}
/** @internal */
export declare function createCachedDirectoryStructureHost(host: DirectoryStructureHost, currentDirectory: string, useCaseSensitiveFileNames: boolean): CachedDirectoryStructureHost | undefined;
/** @internal */
export declare enum ConfigFileProgramReloadLevel {
    None = 0,
    /** Update the file name list from the disk */
    Partial = 1,
    /** Reload completely by re-reading contents of config file from disk and updating program */
    Full = 2
}
/** @internal */
export interface SharedExtendedConfigFileWatcher<T> extends FileWatcher {
    watcher: FileWatcher;
    projects: Set<T>;
}
/**
 * Updates the map of shared extended config file watches with a new set of extended config files from a base config file of the project
 *
 * @internal
 */
export declare function updateSharedExtendedConfigFileWatcher<T>(projectPath: T, options: CompilerOptions | undefined, extendedConfigFilesMap: Map<Path, SharedExtendedConfigFileWatcher<T>>, createExtendedConfigFileWatch: (extendedConfigPath: string, extendedConfigFilePath: Path) => FileWatcher, toPath: (fileName: string) => Path): void;
/**
 * Remove the project from the extended config file watchers and close not needed watches
 *
 * @internal
 */
export declare function clearSharedExtendedConfigFileWatcher<T>(projectPath: T, extendedConfigFilesMap: Map<Path, SharedExtendedConfigFileWatcher<T>>): void;
/**
 * Clean the extendsConfigCache when extended config file has changed
 *
 * @internal
 */
export declare function cleanExtendedConfigCache(extendedConfigCache: Map<string, ExtendedConfigCacheEntry>, extendedConfigFilePath: Path, toPath: (fileName: string) => Path): void;
/**
 * Updates watchers based on the package json files used in module resolution
 *
 * @internal
 */
export declare function updatePackageJsonWatch(lookups: readonly (readonly [Path, object | boolean])[], packageJsonWatches: Map<Path, FileWatcher>, createPackageJsonWatch: (packageJsonPath: Path, data: object | boolean) => FileWatcher): void;
/**
 * Updates the existing missing file watches with the new set of missing files after new program is created
 *
 * @internal
 */
export declare function updateMissingFilePathsWatch(program: Program, missingFileWatches: Map<Path, FileWatcher>, createMissingFileWatch: (missingFilePath: Path) => FileWatcher): void;
/** @internal */
export interface WildcardDirectoryWatcher {
    watcher: FileWatcher;
    flags: WatchDirectoryFlags;
}
/**
 * Updates the existing wild card directory watches with the new set of wild card directories from the config file
 * after new program is created because the config file was reloaded or program was created first time from the config file
 * Note that there is no need to call this function when the program is updated with additional files without reloading config files,
 * as wildcard directories wont change unless reloading config file
 *
 * @internal
 */
export declare function updateWatchingWildcardDirectories(existingWatchedForWildcards: Map<string, WildcardDirectoryWatcher>, wildcardDirectories: Map<string, WatchDirectoryFlags>, watchDirectory: (directory: string, flags: WatchDirectoryFlags) => FileWatcher): void;
/** @internal */
export interface IsIgnoredFileFromWildCardWatchingInput {
    watchedDirPath: Path;
    fileOrDirectory: string;
    fileOrDirectoryPath: Path;
    configFileName: string;
    options: CompilerOptions;
    program: BuilderProgram | Program | readonly string[] | undefined;
    extraFileExtensions?: readonly FileExtensionInfo[];
    currentDirectory: string;
    useCaseSensitiveFileNames: boolean;
    writeLog: (s: string) => void;
    toPath: (fileName: string) => Path;
}
/** @internal */
export declare function isIgnoredFileFromWildCardWatching({ watchedDirPath, fileOrDirectory, fileOrDirectoryPath, configFileName, options, program, extraFileExtensions, currentDirectory, useCaseSensitiveFileNames, writeLog, toPath, }: IsIgnoredFileFromWildCardWatchingInput): boolean;
/** @internal */
export declare function isEmittedFileOfProgram(program: Program | undefined, file: string): boolean;
/** @internal */
export declare enum WatchLogLevel {
    None = 0,
    TriggerOnly = 1,
    Verbose = 2
}
/** @internal */
export interface WatchFactoryHost {
    watchFile(path: string, callback: FileWatcherCallback, pollingInterval?: number, options?: WatchOptions): FileWatcher;
    watchDirectory(path: string, callback: DirectoryWatcherCallback, recursive?: boolean, options?: WatchOptions): FileWatcher;
    getCurrentDirectory?(): string;
    useCaseSensitiveFileNames: boolean | (() => boolean);
}
/** @internal */
export interface WatchFactory<X, Y = undefined> {
    watchFile: (file: string, callback: FileWatcherCallback, pollingInterval: PollingInterval, options: WatchOptions | undefined, detailInfo1: X, detailInfo2?: Y) => FileWatcher;
    watchDirectory: (directory: string, callback: DirectoryWatcherCallback, flags: WatchDirectoryFlags, options: WatchOptions | undefined, detailInfo1: X, detailInfo2?: Y) => FileWatcher;
}
/** @internal */
export type GetDetailWatchInfo<X, Y> = (detailInfo1: X, detailInfo2: Y | undefined) => string;
/** @internal */
export declare function getWatchFactory<X, Y = undefined>(host: WatchFactoryHost, watchLogLevel: WatchLogLevel, log: (s: string) => void, getDetailWatchInfo?: GetDetailWatchInfo<X, Y>): WatchFactory<X, Y>;
/** @internal */
export declare function getFallbackOptions(options: WatchOptions | undefined): WatchOptions;
/** @internal */
export declare function closeFileWatcherOf<T extends {
    watcher: FileWatcher;
}>(objWithWatcher: T): void;
//# sourceMappingURL=watchUtilities.d.ts.map