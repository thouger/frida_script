import { CancellationToken, CustomTransformers, EmitOutput, ExportedModulesFromDeclarationEmit, HostForComputeHash, Path, Program, ResolutionMode, SourceFile } from "./_namespaces/ts";
/** @internal */
export declare function getFileEmitOutput(program: Program, sourceFile: SourceFile, emitOnlyDtsFiles: boolean, cancellationToken?: CancellationToken, customTransformers?: CustomTransformers, forceDtsEmit?: boolean): EmitOutput;
/** @internal */
export interface BuilderState {
    /**
     * Information of the file eg. its version, signature etc
     */
    fileInfos: Map<Path, BuilderState.FileInfo>;
    /**
     * Contains the map of ReferencedSet=Referenced files of the file if module emit is enabled
     * Otherwise undefined
     * Thus non undefined value indicates, module emit
     */
    readonly referencedMap?: BuilderState.ReadonlyManyToManyPathMap | undefined;
    /**
     * Contains the map of exported modules ReferencedSet=exported module files from the file if module emit is enabled
     * Otherwise undefined
     *
     * This is equivalent to referencedMap, but for the emitted .d.ts file.
     */
    readonly exportedModulesMap?: BuilderState.ManyToManyPathMap | undefined;
    /**
     * true if file version is used as signature
     * This helps in delaying the calculation of the d.ts hash as version for the file till reasonable time
     */
    useFileVersionAsSignature?: boolean;
    /**
     * Map of files that have already called update signature.
     * That means hence forth these files are assumed to have
     * no change in their signature for this version of the program
     */
    hasCalledUpdateShapeSignature?: Set<Path>;
    /**
     * Stores signatures before before the update till affected file is commited
     */
    oldSignatures?: Map<Path, string | false>;
    /**
     * Stores exportedModulesMap before the update till affected file is commited
     */
    oldExportedModulesMap?: Map<Path, ReadonlySet<Path> | false>;
    /**
     * Cache of all files excluding default library file for the current program
     */
    allFilesExcludingDefaultLibraryFile?: readonly SourceFile[];
    /**
     * Cache of all the file names
     */
    allFileNames?: readonly string[];
}
/** @internal */
export declare namespace BuilderState {
    /**
     * Information about the source file: Its version and optional signature from last emit
     */
    interface FileInfo {
        readonly version: string;
        signature: string | undefined;
        affectsGlobalScope: true | undefined;
        impliedFormat: ResolutionMode;
    }
    interface ReadonlyManyToManyPathMap {
        getKeys(v: Path): ReadonlySet<Path> | undefined;
        getValues(k: Path): ReadonlySet<Path> | undefined;
        keys(): IterableIterator<Path>;
    }
    interface ManyToManyPathMap extends ReadonlyManyToManyPathMap {
        deleteKey(k: Path): boolean;
        set(k: Path, v: ReadonlySet<Path>): void;
    }
    function createManyToManyPathMap(): ManyToManyPathMap;
    /**
     * Returns true if oldState is reusable, that is the emitKind = module/non module has not changed
     */
    function canReuseOldState(newReferencedMap: ReadonlyManyToManyPathMap | undefined, oldState: BuilderState | undefined): boolean | undefined;
    /**
     * Creates the state of file references and signature for the new program from oldState if it is safe
     */
    function create(newProgram: Program, oldState: Readonly<BuilderState> | undefined, disableUseFileVersionAsSignature: boolean): BuilderState;
    /**
     * Releases needed properties
     */
    function releaseCache(state: BuilderState): void;
    /**
     * Gets the files affected by the path from the program
     */
    function getFilesAffectedBy(state: BuilderState, programOfThisState: Program, path: Path, cancellationToken: CancellationToken | undefined, host: HostForComputeHash): readonly SourceFile[];
    function getFilesAffectedByWithOldState(state: BuilderState, programOfThisState: Program, path: Path, cancellationToken: CancellationToken | undefined, host: HostForComputeHash): readonly SourceFile[];
    function updateSignatureOfFile(state: BuilderState, signature: string | undefined, path: Path): void;
    function computeDtsSignature(programOfThisState: Program, sourceFile: SourceFile, cancellationToken: CancellationToken | undefined, host: HostForComputeHash, onNewSignature: (signature: string, sourceFiles: readonly SourceFile[]) => void): void;
    /**
     * Returns if the shape of the signature has changed since last emit
     */
    function updateShapeSignature(state: BuilderState, programOfThisState: Program, sourceFile: SourceFile, cancellationToken: CancellationToken | undefined, host: HostForComputeHash, useFileVersionAsSignature?: boolean | undefined): boolean;
    /**
     * Coverts the declaration emit result into exported modules map
     */
    function updateExportedModules(state: BuilderState, sourceFile: SourceFile, exportedModulesFromDeclarationEmit: ExportedModulesFromDeclarationEmit | undefined): void;
    function getExportedModules(exportedModulesFromDeclarationEmit: ExportedModulesFromDeclarationEmit | undefined): Set<Path> | undefined;
    /**
     * Get all the dependencies of the sourceFile
     */
    function getAllDependencies(state: BuilderState, programOfThisState: Program, sourceFile: SourceFile): readonly string[];
    /**
     * Gets the files referenced by the the file path
     */
    function getReferencedByPaths(state: Readonly<BuilderState>, referencedFilePath: Path): Path[];
    /**
     * Gets all files of the program excluding the default library file
     */
    function getAllFilesExcludingDefaultLibraryFile(state: BuilderState, programOfThisState: Program, firstSourceFile: SourceFile | undefined): readonly SourceFile[];
}
//# sourceMappingURL=builderState.d.ts.map