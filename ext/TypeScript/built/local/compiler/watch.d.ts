import { BuilderProgram, CancellationToken, CompilerHost, CompilerOptions, CreateProgram, CustomTransformers, Diagnostic, DiagnosticMessage, DiagnosticMessageChain, DiagnosticReporter, DirectoryStructureHost, EmitAndSemanticDiagnosticsBuilderProgram, EmitResult, ExitStatus, ExtendedConfigCacheEntry, FileExtensionInfo, FileIncludeReason, FileWatcher, HasCurrentDirectory, ParsedCommandLine, Program, ProgramHost, ProjectReference, ReportEmitErrorSummary, ReportFileInError, SortedReadonlyArray, SourceFile, System, WatchCompilerHostOfConfigFile, WatchCompilerHostOfFilesAndCompilerOptions, WatchFactory, WatchFactoryHost, WatchHost, WatchOptions, WatchStatusReporter, WriteFileCallback } from "./_namespaces/ts";
/**
 * Create a function that reports error by writing to the system and handles the formatting of the diagnostic
 *
 * @internal
 */
export declare function createDiagnosticReporter(system: System, pretty?: boolean): DiagnosticReporter;
/** @internal */
export declare const screenStartingMessageCodes: number[];
/**
 * Get locale specific time based on whether we are in test mode
 *
 * @internal
 */
export declare function getLocaleTimeString(system: System): string;
/**
 * Create a function that reports watch status by writing to the system and handles the formatting of the diagnostic
 *
 * @internal
 */
export declare function createWatchStatusReporter(system: System, pretty?: boolean): WatchStatusReporter;
/**
 * Parses config file using System interface
 *
 * @internal
 */
export declare function parseConfigFileWithSystem(configFileName: string, optionsToExtend: CompilerOptions, extendedConfigCache: Map<string, ExtendedConfigCacheEntry> | undefined, watchOptionsToExtend: WatchOptions | undefined, system: System, reportDiagnostic: DiagnosticReporter): ParsedCommandLine | undefined;
/** @internal */
export declare function getErrorCountForSummary(diagnostics: readonly Diagnostic[]): number;
/** @internal */
export declare function getFilesInErrorForSummary(diagnostics: readonly Diagnostic[]): (ReportFileInError | undefined)[];
/** @internal */
export declare function getWatchErrorSummaryDiagnosticMessage(errorCount: number): DiagnosticMessage;
/** @internal */
export declare function getErrorSummaryText(errorCount: number, filesInError: readonly (ReportFileInError | undefined)[], newLine: string, host: HasCurrentDirectory): string;
/** @internal */
export declare function isBuilderProgram(program: Program | BuilderProgram): program is BuilderProgram;
/** @internal */
export declare function listFiles<T extends BuilderProgram>(program: Program | T, write: (s: string) => void): void;
/** @internal */
export declare function explainFiles(program: Program, write: (s: string) => void): void;
/** @internal */
export declare function explainIfFileIsRedirectAndImpliedFormat(file: SourceFile, fileNameConvertor?: (fileName: string) => string): DiagnosticMessageChain[] | undefined;
/** @internal */
export declare function getMatchedFileSpec(program: Program, fileName: string): string | undefined;
/** @internal */
export declare function getMatchedIncludeSpec(program: Program, fileName: string): string | true | undefined;
/** @internal */
export declare function fileIncludeReasonToDiagnostics(program: Program, reason: FileIncludeReason, fileNameConvertor?: (fileName: string) => string): DiagnosticMessageChain;
/**
 * Helper that emit files, report diagnostics and lists emitted and/or source files depending on compiler options
 *
 * @internal
 */
export declare function emitFilesAndReportErrors<T extends BuilderProgram>(program: Program | T, reportDiagnostic: DiagnosticReporter, write?: (s: string) => void, reportSummary?: ReportEmitErrorSummary, writeFile?: WriteFileCallback, cancellationToken?: CancellationToken, emitOnlyDtsFiles?: boolean, customTransformers?: CustomTransformers): {
    emitResult: EmitResult;
    diagnostics: SortedReadonlyArray<Diagnostic>;
};
/** @internal */
export declare function emitFilesAndReportErrorsAndGetExitStatus<T extends BuilderProgram>(program: Program | T, reportDiagnostic: DiagnosticReporter, write?: (s: string) => void, reportSummary?: ReportEmitErrorSummary, writeFile?: WriteFileCallback, cancellationToken?: CancellationToken, emitOnlyDtsFiles?: boolean, customTransformers?: CustomTransformers): ExitStatus.Success | ExitStatus.DiagnosticsPresent_OutputsSkipped | ExitStatus.DiagnosticsPresent_OutputsGenerated;
/** @internal */
export declare const noopFileWatcher: FileWatcher;
/** @internal */
export declare const returnNoopFileWatcher: () => FileWatcher;
/** @internal */
export declare function createWatchHost(system?: System, reportWatchStatus?: WatchStatusReporter): WatchHost;
/** @internal */
export type WatchType = WatchTypeRegistry[keyof WatchTypeRegistry];
/** @internal */
export declare const WatchType: WatchTypeRegistry;
/** @internal */
export interface WatchTypeRegistry {
    ConfigFile: "Config file";
    ExtendedConfigFile: "Extended config file";
    SourceFile: "Source file";
    MissingFile: "Missing file";
    WildcardDirectory: "Wild card directory";
    FailedLookupLocations: "Failed Lookup Locations";
    AffectingFileLocation: "File location affecting resolution";
    TypeRoots: "Type roots";
    ConfigFileOfReferencedProject: "Config file of referened project";
    ExtendedConfigOfReferencedProject: "Extended config file of referenced project";
    WildcardDirectoryOfReferencedProject: "Wild card directory of referenced project";
    PackageJson: "package.json file";
    ClosedScriptInfo: "Closed Script info";
    ConfigFileForInferredRoot: "Config file for the inferred project root";
    NodeModules: "node_modules for closed script infos and package.jsons affecting module specifier cache";
    MissingSourceMapFile: "Missing source map file";
    NoopConfigFileForInferredRoot: "Noop Config file for the inferred project root";
    MissingGeneratedFile: "Missing generated file";
    NodeModulesForModuleSpecifierCache: "node_modules for module specifier cache invalidation";
    TypingInstallerLocationFile: "File location for typing installer";
    TypingInstallerLocationDirectory: "Directory location for typing installer";
}
/** @internal */
export interface WatchFactoryWithLog<X, Y = undefined> extends WatchFactory<X, Y> {
    writeLog: (s: string) => void;
}
/** @internal */
export declare function createWatchFactory<Y = undefined>(host: WatchFactoryHost & {
    trace?(s: string): void;
}, options: {
    extendedDiagnostics?: boolean;
    diagnostics?: boolean;
}): WatchFactoryWithLog<WatchType, Y>;
/** @internal */
export declare function createCompilerHostFromProgramHost(host: ProgramHost<any>, getCompilerOptions: () => CompilerOptions, directoryStructureHost?: DirectoryStructureHost): CompilerHost;
/** @internal */
export declare function getSourceFileVersionAsHashFromText(host: Pick<CompilerHost, "createHash">, text: string): string;
/** @internal */
export declare function setGetSourceFileAsHashVersioned(compilerHost: CompilerHost): void;
/**
 * Creates the watch compiler host that can be extended with config file or root file names and options host
 *
 * @internal
 */
export declare function createProgramHost<T extends BuilderProgram = EmitAndSemanticDiagnosticsBuilderProgram>(system: System, createProgram: CreateProgram<T> | undefined): ProgramHost<T>;
/** @internal */
export interface CreateWatchCompilerHostInput<T extends BuilderProgram> {
    system: System;
    createProgram?: CreateProgram<T>;
    reportDiagnostic?: DiagnosticReporter;
    reportWatchStatus?: WatchStatusReporter;
}
/** @internal */
export interface CreateWatchCompilerHostOfConfigFileInput<T extends BuilderProgram> extends CreateWatchCompilerHostInput<T> {
    configFileName: string;
    optionsToExtend?: CompilerOptions;
    watchOptionsToExtend?: WatchOptions;
    extraFileExtensions?: readonly FileExtensionInfo[];
}
/**
 * Creates the watch compiler host from system for config file in watch mode
 *
 * @internal
 */
export declare function createWatchCompilerHostOfConfigFile<T extends BuilderProgram = EmitAndSemanticDiagnosticsBuilderProgram>({ configFileName, optionsToExtend, watchOptionsToExtend, extraFileExtensions, system, createProgram, reportDiagnostic, reportWatchStatus }: CreateWatchCompilerHostOfConfigFileInput<T>): WatchCompilerHostOfConfigFile<T>;
/** @internal */
export interface CreateWatchCompilerHostOfFilesAndCompilerOptionsInput<T extends BuilderProgram> extends CreateWatchCompilerHostInput<T> {
    rootFiles: string[];
    options: CompilerOptions;
    watchOptions: WatchOptions | undefined;
    projectReferences?: readonly ProjectReference[];
}
/**
 * Creates the watch compiler host from system for compiling root files and options in watch mode
 *
 * @internal
 */
export declare function createWatchCompilerHostOfFilesAndCompilerOptions<T extends BuilderProgram = EmitAndSemanticDiagnosticsBuilderProgram>({ rootFiles, options, watchOptions, projectReferences, system, createProgram, reportDiagnostic, reportWatchStatus }: CreateWatchCompilerHostOfFilesAndCompilerOptionsInput<T>): WatchCompilerHostOfFilesAndCompilerOptions<T>;
/** @internal */
export interface IncrementalCompilationOptions {
    rootNames: readonly string[];
    options: CompilerOptions;
    configFileParsingDiagnostics?: readonly Diagnostic[];
    projectReferences?: readonly ProjectReference[];
    host?: CompilerHost;
    reportDiagnostic?: DiagnosticReporter;
    reportErrorSummary?: ReportEmitErrorSummary;
    afterProgramEmitAndDiagnostics?(program: EmitAndSemanticDiagnosticsBuilderProgram): void;
    system?: System;
}
/** @internal */
export declare function performIncrementalCompilation(input: IncrementalCompilationOptions): ExitStatus.Success | ExitStatus.DiagnosticsPresent_OutputsSkipped | ExitStatus.DiagnosticsPresent_OutputsGenerated;
//# sourceMappingURL=watch.d.ts.map