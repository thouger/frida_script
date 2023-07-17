import { AffectedFileResult, BuilderProgram, CancellationToken, CompilerOptions, CompilerOptionsValue, ConfigFileProgramReloadLevel, CreateProgram, CustomTransformers, Diagnostic, DiagnosticReporter, EmitAndSemanticDiagnosticsBuilderProgram, EmitResult, ExitStatus, ParsedCommandLine, Path, Program, ProgramHost, ResolvedConfigFileName, SourceFile, System, UpToDateStatus, WatchHost, WatchOptions, WatchStatusReporter, WriteFileCallback } from "./_namespaces/ts";
export interface BuildOptions {
    dry?: boolean;
    force?: boolean;
    verbose?: boolean;
    /** @internal */ clean?: boolean;
    /** @internal */ watch?: boolean;
    /** @internal */ help?: boolean;
    /** @internal */ preserveWatchOutput?: boolean;
    /** @internal */ listEmittedFiles?: boolean;
    /** @internal */ listFiles?: boolean;
    /** @internal */ explainFiles?: boolean;
    /** @internal */ pretty?: boolean;
    incremental?: boolean;
    assumeChangesOnlyAffectDirectDependencies?: boolean;
    declaration?: boolean;
    declarationMap?: boolean;
    emitDeclarationOnly?: boolean;
    sourceMap?: boolean;
    inlineSourceMap?: boolean;
    traceResolution?: boolean;
    /** @internal */ diagnostics?: boolean;
    /** @internal */ extendedDiagnostics?: boolean;
    /** @internal */ locale?: string;
    /** @internal */ generateCpuProfile?: string;
    /** @internal */ generateTrace?: string;
    [option: string]: CompilerOptionsValue | undefined;
}
/** @internal */
export type ResolvedConfigFilePath = ResolvedConfigFileName & Path;
/**
 * Helper to use now method instead of current date for testing purposes to get consistent baselines
 *
 * @internal
 */
export declare function getCurrentTime(host: {
    now?(): Date;
}): Date;
export type ReportEmitErrorSummary = (errorCount: number, filesInError: (ReportFileInError | undefined)[]) => void;
export interface ReportFileInError {
    fileName: string;
    line: number;
}
export interface SolutionBuilderHostBase<T extends BuilderProgram> extends ProgramHost<T> {
    createDirectory?(path: string): void;
    /**
     * Should provide create directory and writeFile if done of invalidatedProjects is not invoked with
     * writeFileCallback
     */
    writeFile?(path: string, data: string, writeByteOrderMark?: boolean): void;
    getCustomTransformers?: (project: string) => CustomTransformers | undefined;
    getModifiedTime(fileName: string): Date | undefined;
    setModifiedTime(fileName: string, date: Date): void;
    deleteFile(fileName: string): void;
    getParsedCommandLine?(fileName: string): ParsedCommandLine | undefined;
    reportDiagnostic: DiagnosticReporter;
    reportSolutionBuilderStatus: DiagnosticReporter;
    afterProgramEmitAndDiagnostics?(program: T): void;
    /** @deprecated @internal */ beforeEmitBundle?(config: ParsedCommandLine): void;
    /** @deprecated @internal */ afterEmitBundle?(config: ParsedCommandLine): void;
    /** @internal */ now?(): Date;
}
export interface SolutionBuilderHost<T extends BuilderProgram> extends SolutionBuilderHostBase<T> {
    reportErrorSummary?: ReportEmitErrorSummary;
}
export interface SolutionBuilderWithWatchHost<T extends BuilderProgram> extends SolutionBuilderHostBase<T>, WatchHost {
}
/** @internal */
export type BuildOrder = readonly ResolvedConfigFileName[];
/** @internal */
export interface CircularBuildOrder {
    buildOrder: BuildOrder;
    circularDiagnostics: readonly Diagnostic[];
}
/** @internal */
export type AnyBuildOrder = BuildOrder | CircularBuildOrder;
/** @internal */
export declare function isCircularBuildOrder(buildOrder: AnyBuildOrder): buildOrder is CircularBuildOrder;
/** @internal */
export declare function getBuildOrderFromAnyBuildOrder(anyBuildOrder: AnyBuildOrder): BuildOrder;
export interface SolutionBuilder<T extends BuilderProgram> {
    build(project?: string, cancellationToken?: CancellationToken, writeFile?: WriteFileCallback, getCustomTransformers?: (project: string) => CustomTransformers): ExitStatus;
    clean(project?: string): ExitStatus;
    buildReferences(project: string, cancellationToken?: CancellationToken, writeFile?: WriteFileCallback, getCustomTransformers?: (project: string) => CustomTransformers): ExitStatus;
    cleanReferences(project?: string): ExitStatus;
    getNextInvalidatedProject(cancellationToken?: CancellationToken): InvalidatedProject<T> | undefined;
    /** @internal */ getBuildOrder(): AnyBuildOrder;
    /** @internal */ getUpToDateStatusOfProject(project: string): UpToDateStatus;
    /** @internal */ invalidateProject(configFilePath: ResolvedConfigFilePath, reloadLevel?: ConfigFileProgramReloadLevel): void;
    /** @internal */ close(): void;
}
/**
 * Create a function that reports watch status by writing to the system and handles the formating of the diagnostic
 */
export declare function createBuilderStatusReporter(system: System, pretty?: boolean): DiagnosticReporter;
export declare function createSolutionBuilderHost<T extends BuilderProgram = EmitAndSemanticDiagnosticsBuilderProgram>(system?: System, createProgram?: CreateProgram<T>, reportDiagnostic?: DiagnosticReporter, reportSolutionBuilderStatus?: DiagnosticReporter, reportErrorSummary?: ReportEmitErrorSummary): SolutionBuilderHost<T>;
export declare function createSolutionBuilderWithWatchHost<T extends BuilderProgram = EmitAndSemanticDiagnosticsBuilderProgram>(system?: System, createProgram?: CreateProgram<T>, reportDiagnostic?: DiagnosticReporter, reportSolutionBuilderStatus?: DiagnosticReporter, reportWatchStatus?: WatchStatusReporter): SolutionBuilderWithWatchHost<T>;
export declare function createSolutionBuilder<T extends BuilderProgram>(host: SolutionBuilderHost<T>, rootNames: readonly string[], defaultOptions: BuildOptions): SolutionBuilder<T>;
export declare function createSolutionBuilderWithWatch<T extends BuilderProgram>(host: SolutionBuilderWithWatchHost<T>, rootNames: readonly string[], defaultOptions: BuildOptions, baseWatchOptions?: WatchOptions): SolutionBuilder<T>;
export declare enum InvalidatedProjectKind {
    Build = 0,
    /** @deprecated */ UpdateBundle = 1,
    UpdateOutputFileStamps = 2
}
export interface InvalidatedProjectBase {
    readonly kind: InvalidatedProjectKind;
    readonly project: ResolvedConfigFileName;
    /** @internal */ readonly projectPath: ResolvedConfigFilePath;
    /** @internal */ readonly buildOrder: readonly ResolvedConfigFileName[];
    /**
     *  To dispose this project and ensure that all the necessary actions are taken and state is updated accordingly
     */
    done(cancellationToken?: CancellationToken, writeFile?: WriteFileCallback, customTransformers?: CustomTransformers): ExitStatus;
    getCompilerOptions(): CompilerOptions;
    getCurrentDirectory(): string;
}
export interface UpdateOutputFileStampsProject extends InvalidatedProjectBase {
    readonly kind: InvalidatedProjectKind.UpdateOutputFileStamps;
    updateOutputFileStatmps(): void;
}
export interface BuildInvalidedProject<T extends BuilderProgram> extends InvalidatedProjectBase {
    readonly kind: InvalidatedProjectKind.Build;
    getBuilderProgram(): T | undefined;
    getProgram(): Program | undefined;
    getSourceFile(fileName: string): SourceFile | undefined;
    getSourceFiles(): readonly SourceFile[];
    getOptionsDiagnostics(cancellationToken?: CancellationToken): readonly Diagnostic[];
    getGlobalDiagnostics(cancellationToken?: CancellationToken): readonly Diagnostic[];
    getConfigFileParsingDiagnostics(): readonly Diagnostic[];
    getSyntacticDiagnostics(sourceFile?: SourceFile, cancellationToken?: CancellationToken): readonly Diagnostic[];
    getAllDependencies(sourceFile: SourceFile): readonly string[];
    getSemanticDiagnostics(sourceFile?: SourceFile, cancellationToken?: CancellationToken): readonly Diagnostic[];
    getSemanticDiagnosticsOfNextAffectedFile(cancellationToken?: CancellationToken, ignoreSourceFile?: (sourceFile: SourceFile) => boolean): AffectedFileResult<readonly Diagnostic[]>;
    emit(targetSourceFile?: SourceFile, writeFile?: WriteFileCallback, cancellationToken?: CancellationToken, emitOnlyDtsFiles?: boolean, customTransformers?: CustomTransformers): EmitResult | undefined;
}
/** @deprecated */
export interface UpdateBundleProject<T extends BuilderProgram> extends InvalidatedProjectBase {
    readonly kind: InvalidatedProjectKind.UpdateBundle;
    emit(writeFile?: WriteFileCallback, customTransformers?: CustomTransformers): EmitResult | BuildInvalidedProject<T> | undefined;
}
export type InvalidatedProject<T extends BuilderProgram> = UpdateOutputFileStampsProject | BuildInvalidedProject<T> | UpdateBundleProject<T>;
//# sourceMappingURL=tsbuildPublic.d.ts.map