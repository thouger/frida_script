import { BuilderProgram, BuilderProgramHost, BuilderState, BuildInfo, BundleBuildInfo, CompilerHost, CompilerOptions, Diagnostic, DiagnosticCategory, DiagnosticMessageChain, EmitAndSemanticDiagnosticsBuilderProgram, HostForComputeHash, Path, Program, ProjectReference, ReadBuildProgramHost, RepopulateModuleNotFoundDiagnosticChain, SemanticDiagnosticsBuilderProgram, SourceFile, WriteFileCallbackData } from "./_namespaces/ts";
/** @internal */
export interface ReusableDiagnostic extends ReusableDiagnosticRelatedInformation {
    /** May store more in future. For now, this will simply be `true` to indicate when a diagnostic is an unused-identifier diagnostic. */
    reportsUnnecessary?: {};
    reportDeprecated?: {};
    source?: string;
    relatedInformation?: ReusableDiagnosticRelatedInformation[];
    skippedOn?: keyof CompilerOptions;
}
/** @internal */
export interface ReusableDiagnosticRelatedInformation {
    category: DiagnosticCategory;
    code: number;
    file: string | undefined;
    start: number | undefined;
    length: number | undefined;
    messageText: string | ReusableDiagnosticMessageChain;
}
/** @internal */
export interface ReusableRepopulateModuleNotFoundChain {
    info: RepopulateModuleNotFoundDiagnosticChain;
    next?: ReusableDiagnosticMessageChain[];
}
/** @internal */
export type SerializedDiagnosticMessageChain = Omit<DiagnosticMessageChain, "next" | "repopulateInfo"> & {
    next?: ReusableDiagnosticMessageChain[];
};
/** @internal */
export type ReusableDiagnosticMessageChain = SerializedDiagnosticMessageChain | ReusableRepopulateModuleNotFoundChain;
/**
 * Signature (Hash of d.ts emitted), is string if it was emitted using same d.ts.map option as what compilerOptions indicate, otherwise tuple of string
 *
 * @internal
 */
export type EmitSignature = string | [signature: string];
/** @internal */
export interface ReusableBuilderProgramState extends BuilderState {
    /**
     * Cache of bind and check diagnostics for files with their Path being the key
     */
    semanticDiagnosticsPerFile?: Map<Path, readonly ReusableDiagnostic[] | readonly Diagnostic[]> | undefined;
    /**
     * The map has key by source file's path that has been changed
     */
    changedFilesSet?: Set<Path>;
    /**
     * program corresponding to this state
     */
    program?: Program | undefined;
    /**
     * compilerOptions for the program
     */
    compilerOptions: CompilerOptions;
    /**
     * Files pending to be emitted
     */
    affectedFilesPendingEmit?: ReadonlyMap<Path, BuilderFileEmit>;
    /**
     * emitKind pending for a program with --out
     */
    programEmitPending?: BuilderFileEmit;
    hasReusableDiagnostic?: true;
    /**
     * Hash of d.ts emitted for the file, use to track when emit of d.ts changes
     */
    emitSignatures?: Map<Path, EmitSignature>;
    /**
     * Hash of d.ts emit with --out
     */
    outSignature?: EmitSignature;
    /**
     * Name of the file whose dts was the latest to change
     */
    latestChangedDtsFile: string | undefined;
    /**
     * @deprecated
     * Bundle information either from oldState or current one so it can be used to complete the information in buildInfo when emitting only js or dts files
     */
    bundle?: BundleBuildInfo;
}
/** @internal */
export declare const enum BuilderFileEmit {
    None = 0,
    Js = 1,
    JsMap = 2,
    JsInlineMap = 4,
    Dts = 8,
    DtsMap = 16,
    AllJs = 7,
    AllDts = 24,
    All = 31
}
/**
 * State to store the changed files, affected files and cache semantic diagnostics
 *
 * @internal
 */
export interface BuilderProgramState extends BuilderState, ReusableBuilderProgramState {
    /**
     * Cache of bind and check diagnostics for files with their Path being the key
     */
    semanticDiagnosticsPerFile: Map<Path, readonly Diagnostic[]> | undefined;
    /**
     * The map has key by source file's path that has been changed
     */
    changedFilesSet: Set<Path>;
    /**
     * Set of affected files being iterated
     */
    affectedFiles?: readonly SourceFile[] | undefined;
    /**
     * Current index to retrieve affected file from
     */
    affectedFilesIndex: number | undefined;
    /**
     * Current changed file for iterating over affected files
     */
    currentChangedFilePath?: Path | undefined;
    /**
     * Already seen affected files
     */
    seenAffectedFiles: Set<Path> | undefined;
    /**
     * whether this program has cleaned semantic diagnostics cache for lib files
     */
    cleanedDiagnosticsOfLibFiles?: boolean;
    /**
     * True if the semantic diagnostics were copied from the old state
     */
    semanticDiagnosticsFromOldState?: Set<Path>;
    /**
     * Records if change in dts emit was detected
     */
    hasChangedEmitSignature?: boolean;
    /**
     * Files pending to be emitted
     */
    affectedFilesPendingEmit?: Map<Path, BuilderFileEmit>;
    /**
     * true if build info is emitted
     */
    buildInfoEmitPending: boolean;
    /**
     * Already seen emitted files
     */
    seenEmittedFiles: Map<Path, BuilderFileEmit> | undefined;
    /** Stores list of files that change signature during emit - test only */
    filesChangingSignature?: Set<Path>;
}
/** @internal */
export type SavedBuildProgramEmitState = Pick<BuilderProgramState, "affectedFilesPendingEmit" | "seenEmittedFiles" | "programEmitPending" | "emitSignatures" | "outSignature" | "latestChangedDtsFile" | "hasChangedEmitSignature"> & {
    changedFilesSet: BuilderProgramState["changedFilesSet"] | undefined;
};
/**
 * Get flags determining what all needs to be emitted
 *
 * @internal
 */
export declare function getBuilderFileEmit(options: CompilerOptions): BuilderFileEmit;
/**
 * Determing what all is pending to be emitted based on previous options or previous file emit flags
 *
 * @internal
 */
export declare function getPendingEmitKind(optionsOrEmitKind: CompilerOptions | BuilderFileEmit, oldOptionsOrEmitKind: CompilerOptions | BuilderFileEmit | undefined): BuilderFileEmit;
/** @internal */
export type ProgramBuildInfoFileId = number & {
    __programBuildInfoFileIdBrand: any;
};
/** @internal */
export type ProgramBuildInfoFileIdListId = number & {
    __programBuildInfoFileIdListIdBrand: any;
};
/** @internal */
export type ProgramBuildInfoDiagnostic = ProgramBuildInfoFileId | [fileId: ProgramBuildInfoFileId, diagnostics: readonly ReusableDiagnostic[]];
/**
 * fileId if pending emit is same as what compilerOptions suggest
 * [fileId] if pending emit is only dts file emit
 * [fileId, emitKind] if any other type emit is pending
 *
 * @internal
 */
export type ProgramBuilderInfoFilePendingEmit = ProgramBuildInfoFileId | [fileId: ProgramBuildInfoFileId] | [fileId: ProgramBuildInfoFileId, emitKind: BuilderFileEmit];
/** @internal */
export type ProgramBuildInfoReferencedMap = [fileId: ProgramBuildInfoFileId, fileIdListId: ProgramBuildInfoFileIdListId][];
/** @internal */
export type ProgramMultiFileEmitBuildInfoBuilderStateFileInfo = Omit<BuilderState.FileInfo, "signature"> & {
    /**
     * Signature is
     * - undefined if FileInfo.version === FileInfo.signature
     * - false if FileInfo has signature as undefined (not calculated)
     * - string actual signature
     */
    signature: string | false | undefined;
};
/**
 * [fileId, signature] if different from file's signature
 * fileId if file wasnt emitted
 *
 * @internal
 */
export type ProgramBuildInfoEmitSignature = ProgramBuildInfoFileId | [fileId: ProgramBuildInfoFileId, signature: EmitSignature | []];
/**
 * ProgramMultiFileEmitBuildInfoFileInfo is string if FileInfo.version === FileInfo.signature && !FileInfo.affectsGlobalScope otherwise encoded FileInfo
 *
 * @internal
 */
export type ProgramMultiFileEmitBuildInfoFileInfo = string | ProgramMultiFileEmitBuildInfoBuilderStateFileInfo;
/** @internal */
export type ProgramBuildInfoRootStartEnd = [start: ProgramBuildInfoFileId, end: ProgramBuildInfoFileId];
/**
 * Either start and end of FileId for consecutive fileIds to be included as root or single fileId that is root
 * @internal
 */
export type ProgramBuildInfoRoot = ProgramBuildInfoRootStartEnd | ProgramBuildInfoFileId;
/** @internal */
export interface ProgramMultiFileEmitBuildInfo {
    fileNames: readonly string[];
    fileInfos: readonly ProgramMultiFileEmitBuildInfoFileInfo[];
    root: readonly ProgramBuildInfoRoot[];
    options: CompilerOptions | undefined;
    fileIdsList: readonly (readonly ProgramBuildInfoFileId[])[] | undefined;
    referencedMap: ProgramBuildInfoReferencedMap | undefined;
    exportedModulesMap: ProgramBuildInfoReferencedMap | undefined;
    semanticDiagnosticsPerFile: ProgramBuildInfoDiagnostic[] | undefined;
    affectedFilesPendingEmit: ProgramBuilderInfoFilePendingEmit[] | undefined;
    changeFileSet: readonly ProgramBuildInfoFileId[] | undefined;
    emitSignatures: readonly ProgramBuildInfoEmitSignature[] | undefined;
    latestChangedDtsFile?: string | undefined;
}
/**
 * ProgramBundleEmitBuildInfoFileInfo is string if !FileInfo.impliedFormat otherwise encoded FileInfo
 *
 * @internal
 */
export type ProgramBundleEmitBuildInfoFileInfo = string | BuilderState.FileInfo;
/**
 * false if it is the emit corresponding to compilerOptions
 * value otherwise
 *
 * @internal
 */
export type ProgramBuildInfoBundlePendingEmit = BuilderFileEmit | false;
/** @internal */
export interface ProgramBundleEmitBuildInfo {
    fileNames: readonly string[];
    fileInfos: readonly ProgramBundleEmitBuildInfoFileInfo[];
    root: readonly ProgramBuildInfoRoot[];
    options: CompilerOptions | undefined;
    outSignature: EmitSignature | undefined;
    latestChangedDtsFile: string | undefined;
    pendingEmit: ProgramBuildInfoBundlePendingEmit | undefined;
}
/** @internal */
export type ProgramBuildInfo = ProgramMultiFileEmitBuildInfo | ProgramBundleEmitBuildInfo;
/** @internal */
export declare function isProgramBundleEmitBuildInfo(info: ProgramBuildInfo): info is ProgramBundleEmitBuildInfo;
/** @internal */
export declare enum BuilderProgramKind {
    SemanticDiagnosticsBuilderProgram = 0,
    EmitAndSemanticDiagnosticsBuilderProgram = 1
}
/** @internal */
export interface BuilderCreationParameters {
    newProgram: Program;
    host: BuilderProgramHost;
    oldProgram: BuilderProgram | undefined;
    configFileParsingDiagnostics: readonly Diagnostic[];
}
/** @internal */
export declare function getBuilderCreationParameters(newProgramOrRootNames: Program | readonly string[] | undefined, hostOrOptions: BuilderProgramHost | CompilerOptions | undefined, oldProgramOrHost?: BuilderProgram | CompilerHost, configFileParsingDiagnosticsOrOldProgram?: readonly Diagnostic[] | BuilderProgram, configFileParsingDiagnostics?: readonly Diagnostic[], projectReferences?: readonly ProjectReference[]): BuilderCreationParameters;
/** @internal */
export declare function computeSignatureWithDiagnostics(program: Program, sourceFile: SourceFile, text: string, host: HostForComputeHash, data: WriteFileCallbackData | undefined): string;
/** @internal */
export declare function computeSignature(text: string, host: HostForComputeHash, data?: WriteFileCallbackData): string;
/** @internal */
export declare function createBuilderProgram(kind: BuilderProgramKind.SemanticDiagnosticsBuilderProgram, builderCreationParameters: BuilderCreationParameters): SemanticDiagnosticsBuilderProgram;
/** @internal */
export declare function createBuilderProgram(kind: BuilderProgramKind.EmitAndSemanticDiagnosticsBuilderProgram, builderCreationParameters: BuilderCreationParameters): EmitAndSemanticDiagnosticsBuilderProgram;
/** @internal */
export declare function toBuilderStateFileInfoForMultiEmit(fileInfo: ProgramMultiFileEmitBuildInfoFileInfo): BuilderState.FileInfo;
/** @internal */
export declare function toBuilderFileEmit(value: ProgramBuilderInfoFilePendingEmit, fullEmitForOptions: BuilderFileEmit): BuilderFileEmit;
/** @internal */
export declare function toProgramEmitPending(value: ProgramBuildInfoBundlePendingEmit, options: CompilerOptions | undefined): BuilderFileEmit | undefined;
/** @internal */
export declare function createBuilderProgramUsingProgramBuildInfo(buildInfo: BuildInfo, buildInfoPath: string, host: ReadBuildProgramHost): EmitAndSemanticDiagnosticsBuilderProgram;
/** @internal */
export declare function getBuildInfoFileVersionMap(program: ProgramBuildInfo, buildInfoPath: string, host: Pick<ReadBuildProgramHost, "useCaseSensitiveFileNames" | "getCurrentDirectory">): {
    fileInfos: Map<Path, string>;
    roots: Path[];
};
/** @internal */
export declare function createRedirectedBuilderProgram(getState: () => {
    program?: Program | undefined;
    compilerOptions: CompilerOptions;
}, configFileParsingDiagnostics: readonly Diagnostic[]): BuilderProgram;
//# sourceMappingURL=builder.d.ts.map