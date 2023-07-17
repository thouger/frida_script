import { BuildOptions, CommandLineOption, CommandLineOptionOfCustomType, CommandLineOptionOfListType, CompilerOptions, CompilerOptionsValue, ConfigFileSpecs, Diagnostic, DiagnosticMessage, DidYouMeanOptionsDiagnostics, Expression, FileExtensionInfo, JsonSourceFile, ParseConfigHost, ParsedCommandLine, Path, ProjectReference, PropertyAssignment, TsConfigOnlyOption, TsConfigSourceFile, TypeAcquisition, WatchOptions } from "./_namespaces/ts";
/** @internal */
export declare const compileOnSaveCommandLineOption: CommandLineOption;
/** @internal */
export declare const inverseJsxOptionMap: Map<string, string>;
/**
 * An array of supported "lib" reference file names used to determine the order for inclusion
 * when referenced, as well as for spelling suggestions. This ensures the correct ordering for
 * overload resolution when a type declared in one lib is extended by another.
 *
 * @internal
 */
export declare const libs: string[];
/**
 * A map of lib names to lib files. This map is used both for parsing the "lib" command line
 * option as well as for resolving lib reference directives.
 *
 * @internal
 */
export declare const libMap: Map<string, string>;
/** @internal */
export declare const optionsForWatch: CommandLineOption[];
/** @internal */
export declare const commonOptionsWithBuild: CommandLineOption[];
/** @internal */
export declare const targetOptionDeclaration: CommandLineOptionOfCustomType;
/** @internal */
export declare const moduleOptionDeclaration: CommandLineOptionOfCustomType;
/** @internal */
export declare const optionDeclarations: CommandLineOption[];
/** @internal */
export declare const semanticDiagnosticsOptionDeclarations: readonly CommandLineOption[];
/** @internal */
export declare const affectsEmitOptionDeclarations: readonly CommandLineOption[];
/** @internal */
export declare const affectsDeclarationPathOptionDeclarations: readonly CommandLineOption[];
/** @internal */
export declare const moduleResolutionOptionDeclarations: readonly CommandLineOption[];
/** @internal */
export declare const sourceFileAffectingCompilerOptions: readonly CommandLineOption[];
/** @internal */
export declare const optionsAffectingProgramStructure: readonly CommandLineOption[];
/** @internal */
export declare const transpileOptionValueCompilerOptions: readonly CommandLineOption[];
/** @internal */
export declare const optionsForBuild: CommandLineOption[];
/** @internal */
export declare const buildOpts: CommandLineOption[];
/** @internal */
export declare const typeAcquisitionDeclarations: CommandLineOption[];
/** @internal */
export interface OptionsNameMap {
    optionsNameMap: Map<string, CommandLineOption>;
    shortOptionNames: Map<string, string>;
}
/** @internal */
export declare function createOptionNameMap(optionDeclarations: readonly CommandLineOption[]): OptionsNameMap;
/** @internal */
export declare function getOptionsNameMap(): OptionsNameMap;
/** @internal */
export declare const defaultInitCompilerOptions: CompilerOptions;
/** @internal */
export declare function createCompilerDiagnosticForInvalidCustomType(opt: CommandLineOptionOfCustomType): Diagnostic;
/** @internal */
export declare function parseCustomTypeOption(opt: CommandLineOptionOfCustomType, value: string, errors: Diagnostic[]): string | number | undefined;
/** @internal */
export declare function parseListTypeOption(opt: CommandLineOptionOfListType, value: string | undefined, errors: Diagnostic[]): string | (string | number)[] | undefined;
/** @internal */
export interface OptionsBase {
    [option: string]: CompilerOptionsValue | TsConfigSourceFile | undefined;
}
/** @internal */
export interface ParseCommandLineWorkerDiagnostics extends DidYouMeanOptionsDiagnostics {
    getOptionsNameMap: () => OptionsNameMap;
    optionTypeMismatchDiagnostic: DiagnosticMessage;
}
/** @internal */
export declare function parseCommandLineWorker(diagnostics: ParseCommandLineWorkerDiagnostics, commandLine: readonly string[], readFile?: (path: string) => string | undefined): {
    options: OptionsBase;
    watchOptions: WatchOptions | undefined;
    fileNames: string[];
    errors: Diagnostic[];
};
/** @internal */
export declare const compilerOptionsDidYouMeanDiagnostics: ParseCommandLineWorkerDiagnostics;
export declare function parseCommandLine(commandLine: readonly string[], readFile?: (path: string) => string | undefined): ParsedCommandLine;
/** @internal */
export declare function getOptionFromName(optionName: string, allowShort?: boolean): CommandLineOption | undefined;
/** @internal */
export interface ParsedBuildCommand {
    buildOptions: BuildOptions;
    watchOptions: WatchOptions | undefined;
    projects: string[];
    errors: Diagnostic[];
}
/** @internal */
export declare function parseBuildCommand(args: readonly string[]): ParsedBuildCommand;
/** @internal */
export declare function getDiagnosticText(_message: DiagnosticMessage, ..._args: any[]): string;
export type DiagnosticReporter = (diagnostic: Diagnostic) => void;
/**
 * Reports config file diagnostics
 */
export interface ConfigFileDiagnosticsReporter {
    /**
     * Reports unrecoverable error when parsing config file
     */
    onUnRecoverableConfigFileDiagnostic: DiagnosticReporter;
}
/**
 * Interface extending ParseConfigHost to support ParseConfigFile that reads config file and reports errors
 */
export interface ParseConfigFileHost extends ParseConfigHost, ConfigFileDiagnosticsReporter {
    getCurrentDirectory(): string;
}
/**
 * Reads the config file, reports errors if any and exits if the config file cannot be found
 */
export declare function getParsedCommandLineOfConfigFile(configFileName: string, optionsToExtend: CompilerOptions | undefined, host: ParseConfigFileHost, extendedConfigCache?: Map<string, ExtendedConfigCacheEntry>, watchOptionsToExtend?: WatchOptions, extraFileExtensions?: readonly FileExtensionInfo[]): ParsedCommandLine | undefined;
/**
 * Read tsconfig.json file
 * @param fileName The path to the config file
 */
export declare function readConfigFile(fileName: string, readFile: (path: string) => string | undefined): {
    config?: any;
    error?: Diagnostic;
};
/**
 * Parse the text of the tsconfig.json file
 * @param fileName The path to the config file
 * @param jsonText The text of the config file
 */
export declare function parseConfigFileTextToJson(fileName: string, jsonText: string): {
    config?: any;
    error?: Diagnostic;
};
/**
 * Read tsconfig.json file
 * @param fileName The path to the config file
 */
export declare function readJsonConfigFile(fileName: string, readFile: (path: string) => string | undefined): TsConfigSourceFile;
/** @internal */
export declare function tryReadFile(fileName: string, readFile: (path: string) => string | undefined): string | Diagnostic;
/** @internal */
export interface JsonConversionNotifier {
    rootOptions: TsConfigOnlyOption;
    onPropertySet(keyText: string, value: any, propertyAssignment: PropertyAssignment, parentOption: TsConfigOnlyOption | undefined, option: CommandLineOption | undefined): void;
}
/**
 * Convert the json syntax tree into the json value
 */
export declare function convertToObject(sourceFile: JsonSourceFile, errors: Diagnostic[]): any;
/**
 * Convert the json syntax tree into the json value and report errors
 * This returns the json value (apart from checking errors) only if returnValue provided is true.
 * Otherwise it just checks the errors and returns undefined
 *
 * @internal
 */
export declare function convertToJson(sourceFile: JsonSourceFile, rootExpression: Expression | undefined, errors: Diagnostic[], returnValue: boolean, jsonConversionNotifier: JsonConversionNotifier | undefined): any;
/** @internal */
export interface TSConfig {
    compilerOptions: CompilerOptions;
    compileOnSave: boolean | undefined;
    exclude?: readonly string[];
    files: readonly string[] | undefined;
    include?: readonly string[];
    references: readonly ProjectReference[] | undefined;
}
/** @internal */
export interface ConvertToTSConfigHost {
    getCurrentDirectory(): string;
    useCaseSensitiveFileNames: boolean;
}
/**
 * Generate an uncommented, complete tsconfig for use with "--showConfig"
 * @param configParseResult options to be generated into tsconfig.json
 * @param configFileName name of the parsed config file - output paths will be generated relative to this
 * @param host provides current directory and case sensitivity services
 *
 * @internal
 */
export declare function convertToTSConfig(configParseResult: ParsedCommandLine, configFileName: string, host: ConvertToTSConfigHost): TSConfig;
/** @internal */
export declare function optionMapToObject(optionMap: Map<string, CompilerOptionsValue>): object;
/** @internal */
export declare function getNameOfCompilerOptionValue(value: CompilerOptionsValue, customTypeMap: Map<string, string | number>): string | undefined;
/** @internal */
export declare function serializeCompilerOptions(options: CompilerOptions, pathOptions?: {
    configFilePath: string;
    useCaseSensitiveFileNames: boolean;
}): Map<string, CompilerOptionsValue>;
/**
 * Generate a list of the compiler options whose value is not the default.
 * @param options compilerOptions to be evaluated.
/** @internal */
export declare function getCompilerOptionsDiffValue(options: CompilerOptions, newLine: string): string;
/**
 * Generate tsconfig configuration when running command line "--init"
 * @param options commandlineOptions to be generated into tsconfig.json
 * @param fileNames array of filenames to be generated into tsconfig.json
 *
 * @internal
 */
export declare function generateTSConfig(options: CompilerOptions, fileNames: readonly string[], newLine: string): string;
/** @internal */
export declare function convertToOptionsWithAbsolutePaths(options: CompilerOptions, toAbsolutePath: (path: string) => string): CompilerOptions;
/**
 * Parse the contents of a config file (tsconfig.json).
 * @param json The contents of the config file to parse
 * @param host Instance of ParseConfigHost used to enumerate files in folder.
 * @param basePath A root directory to resolve relative path entries in the config
 *    file to. e.g. outDir
 */
export declare function parseJsonConfigFileContent(json: any, host: ParseConfigHost, basePath: string, existingOptions?: CompilerOptions, configFileName?: string, resolutionStack?: Path[], extraFileExtensions?: readonly FileExtensionInfo[], extendedConfigCache?: Map<string, ExtendedConfigCacheEntry>, existingWatchOptions?: WatchOptions): ParsedCommandLine;
/**
 * Parse the contents of a config file (tsconfig.json).
 * @param jsonNode The contents of the config file to parse
 * @param host Instance of ParseConfigHost used to enumerate files in folder.
 * @param basePath A root directory to resolve relative path entries in the config
 *    file to. e.g. outDir
 */
export declare function parseJsonSourceFileConfigFileContent(sourceFile: TsConfigSourceFile, host: ParseConfigHost, basePath: string, existingOptions?: CompilerOptions, configFileName?: string, resolutionStack?: Path[], extraFileExtensions?: readonly FileExtensionInfo[], extendedConfigCache?: Map<string, ExtendedConfigCacheEntry>, existingWatchOptions?: WatchOptions): ParsedCommandLine;
/** @internal */
export declare function setConfigFileInOptions(options: CompilerOptions, configFile: TsConfigSourceFile | undefined): void;
/** @internal */
export declare const defaultIncludeSpec = "**/*";
/** @internal */
export declare function canJsonReportNoInputFiles(raw: any): boolean;
/** @internal */
export declare function updateErrorForNoInputFiles(fileNames: string[], configFileName: string, configFileSpecs: ConfigFileSpecs, configParseDiagnostics: Diagnostic[], canJsonReportNoInutFiles: boolean): boolean;
export interface ParsedTsconfig {
    raw: any;
    options?: CompilerOptions;
    watchOptions?: WatchOptions;
    typeAcquisition?: TypeAcquisition;
    /**
     * Note that the case of the config path has not yet been normalized, as no files have been imported into the project yet
     */
    extendedConfigPath?: string | string[];
}
export interface ExtendedConfigCacheEntry {
    extendedResult: TsConfigSourceFile;
    extendedConfig: ParsedTsconfig | undefined;
}
export declare function convertCompilerOptionsFromJson(jsonOptions: any, basePath: string, configFileName?: string): {
    options: CompilerOptions;
    errors: Diagnostic[];
};
export declare function convertTypeAcquisitionFromJson(jsonOptions: any, basePath: string, configFileName?: string): {
    options: TypeAcquisition;
    errors: Diagnostic[];
};
/** @internal */
export declare function convertJsonOption(opt: CommandLineOption, value: any, basePath: string, errors: Diagnostic[], propertyAssignment?: PropertyAssignment, valueExpression?: Expression, sourceFile?: TsConfigSourceFile): CompilerOptionsValue;
/**
 * Gets the file names from the provided config file specs that contain, files, include, exclude and
 * other properties needed to resolve the file names
 * @param configFileSpecs The config file specs extracted with file names to include, wildcards to include/exclude and other details
 * @param basePath The base path for any relative file specifications.
 * @param options Compiler options.
 * @param host The host used to resolve files and directories.
 * @param extraFileExtensions optionaly file extra file extension information from host
 *
 * @internal
 */
export declare function getFileNamesFromConfigSpecs(configFileSpecs: ConfigFileSpecs, basePath: string, options: CompilerOptions, host: ParseConfigHost, extraFileExtensions?: readonly FileExtensionInfo[]): string[];
/** @internal */
export declare function isExcludedFile(pathToCheck: string, spec: ConfigFileSpecs, basePath: string, useCaseSensitiveFileNames: boolean, currentDirectory: string): boolean;
/** @internal */
export declare function matchesExclude(pathToCheck: string, excludeSpecs: readonly string[] | undefined, useCaseSensitiveFileNames: boolean, currentDirectory: string): boolean;
/**
 * Produces a cleaned version of compiler options with personally identifying info (aka, paths) removed.
 * Also converts enum values back to strings.
 *
 * @internal
 */
export declare function convertCompilerOptionsForTelemetry(opts: CompilerOptions): CompilerOptions;
//# sourceMappingURL=commandLineParser.d.ts.map