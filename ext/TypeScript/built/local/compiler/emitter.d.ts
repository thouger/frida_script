import * as ts from "./_namespaces/ts";
import { BuildInfo, Bundle, BundleBuildInfo, CompilerHost, CompilerOptions, CustomTransformers, EmitFileNames, EmitHost, EmitOnly, EmitResolver, EmitResult, EmitTransformers, Extension, GetCanonicalFileName, OutputFile, ParsedCommandLine, Printer, PrinterOptions, PrintHandlers, ProgramBuildInfo, ProjectReference, SourceFile } from "./_namespaces/ts";
/** @internal */
export declare function isBuildInfoFile(file: string): boolean;
/**
 * Iterates over the source files that are expected to have an emit output.
 *
 * @param host An EmitHost.
 * @param action The action to execute.
 * @param sourceFilesOrTargetSourceFile
 *   If an array, the full list of source files to emit.
 *   Else, calls `getSourceFilesToEmit` with the (optional) target source file to determine the list of source files to emit.
 *
 * @internal
 */
export declare function forEachEmittedFile<T>(host: EmitHost, action: (emitFileNames: EmitFileNames, sourceFileOrBundle: SourceFile | Bundle | undefined) => T, sourceFilesOrTargetSourceFile?: readonly SourceFile[] | SourceFile, forceDtsEmit?: boolean, onlyBuildInfo?: boolean, includeBuildInfo?: boolean): T | undefined;
export declare function getTsBuildInfoEmitOutputFilePath(options: CompilerOptions): string | undefined;
/** @internal */
export declare function getOutputPathsForBundle(options: CompilerOptions, forceDtsPaths: boolean): EmitFileNames;
/** @internal */
export declare function getOutputPathsFor(sourceFile: SourceFile | Bundle, host: EmitHost, forceDtsPaths: boolean): EmitFileNames;
/** @internal */
export declare function getOutputExtension(fileName: string, options: CompilerOptions): Extension;
/** @internal */
export declare function getOutputDeclarationFileName(inputFileName: string, configFile: ParsedCommandLine, ignoreCase: boolean, getCommonSourceDirectory?: () => string): string;
/** @internal */
export declare function getCommonSourceDirectory(options: CompilerOptions, emittedFiles: () => readonly string[], currentDirectory: string, getCanonicalFileName: GetCanonicalFileName, checkSourceFilesBelongToPath?: (commonSourceDirectory: string) => void): string;
/** @internal */
export declare function getCommonSourceDirectoryOfConfig({ options, fileNames }: ParsedCommandLine, ignoreCase: boolean): string;
/** @internal */
export declare function getAllProjectOutputs(configFile: ParsedCommandLine, ignoreCase: boolean): readonly string[];
export declare function getOutputFileNames(commandLine: ParsedCommandLine, inputFileName: string, ignoreCase: boolean): readonly string[];
/** @internal */
export declare function getFirstProjectOutput(configFile: ParsedCommandLine, ignoreCase: boolean): string;
/** @internal */
export declare function emitFiles(resolver: EmitResolver, host: EmitHost, targetSourceFile: SourceFile | undefined, { scriptTransformers, declarationTransformers }: EmitTransformers, emitOnly?: boolean | EmitOnly, onlyBuildInfo?: boolean, forceDtsEmit?: boolean): EmitResult;
/** @internal */
export declare function createBuildInfo(program: ProgramBuildInfo | undefined, bundle: BundleBuildInfo | undefined): BuildInfo;
/** @internal */
export declare function getBuildInfoText(buildInfo: BuildInfo): string;
/** @internal */
export declare function getBuildInfo(buildInfoFile: string, buildInfoText: string): ts.BuildInfo | undefined;
/** @internal */
export declare const notImplementedResolver: EmitResolver;
/**
 * File that isnt present resulting in error or output files
 *
 * @deprecated
 * @internal
 */
export type EmitUsingBuildInfoResult = string | readonly OutputFile[];
/** @deprecated @internal */
export declare function emitUsingBuildInfo(config: ParsedCommandLine, host: CompilerHost, getCommandLine: (ref: ProjectReference) => ParsedCommandLine | undefined, customTransformers?: CustomTransformers): EmitUsingBuildInfoResult;
/** @internal */
export declare const createPrinterWithDefaults: () => ts.Printer;
/** @internal */
export declare const createPrinterWithRemoveComments: () => ts.Printer;
/** @internal */
export declare const createPrinterWithRemoveCommentsNeverAsciiEscape: () => ts.Printer;
/** @internal */
export declare const createPrinterWithRemoveCommentsOmitTrailingSemicolon: () => ts.Printer;
export declare function createPrinter(printerOptions?: PrinterOptions, handlers?: PrintHandlers): Printer;
//# sourceMappingURL=emitter.d.ts.map