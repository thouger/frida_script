import { CompilerOptions, CompletionEntryData, Diagnostic, DocCommentTemplateOptions, EmitOutput, EndOfLineState, FileReference, FormatCodeSettings, HostCancellationToken, IScriptSnapshot, JsTyping, LanguageService, LanguageServiceHost, ModuleResolutionHost, ParseConfigHost, ResolvedModuleFull, ResolvedTypeReferenceDirective, ScriptKind, SemanticClassificationFormat, SignatureHelpItemsOptions, TextRange, TextSpan, UserPreferences } from "./_namespaces/ts";
/** @internal */
export interface ScriptSnapshotShim {
    /** Gets a portion of the script snapshot specified by [start, end). */
    getText(start: number, end: number): string;
    /** Gets the length of this script snapshot. */
    getLength(): number;
    /**
     * Returns a JSON-encoded value of the type:
     *   { span: { start: number; length: number }; newLength: number }
     *
     * Or undefined value if there was no change.
     */
    getChangeRange(oldSnapshot: ScriptSnapshotShim): string | undefined;
    /** Releases all resources held by this script snapshot */
    dispose?(): void;
}
/** @internal */
export interface Logger {
    log(s: string): void;
    trace(s: string): void;
    error(s: string): void;
}
/**
 * Public interface of the host of a language service shim instance.
 *
 * @internal
 */
export interface LanguageServiceShimHost extends Logger {
    getCompilationSettings(): string;
    /** Returns a JSON-encoded value of the type: string[] */
    getScriptFileNames(): string;
    getScriptKind?(fileName: string): ScriptKind;
    getScriptVersion(fileName: string): string;
    getScriptSnapshot(fileName: string): ScriptSnapshotShim;
    getLocalizedDiagnosticMessages(): string;
    getCancellationToken(): HostCancellationToken;
    getCurrentDirectory(): string;
    getDirectories(path: string): string;
    getDefaultLibFileName(options: string): string;
    getNewLine?(): string;
    getProjectVersion?(): string;
    useCaseSensitiveFileNames?(): boolean;
    getTypeRootsVersion?(): number;
    readDirectory(rootDir: string, extension: string, basePaths?: string, excludeEx?: string, includeFileEx?: string, includeDirEx?: string, depth?: number): string;
    readFile(path: string, encoding?: string): string | undefined;
    fileExists(path: string): boolean;
    getModuleResolutionsForFile?(fileName: string): string;
    getTypeReferenceDirectiveResolutionsForFile?(fileName: string): string;
    directoryExists(directoryName: string): boolean;
}
/**
 * Public interface of the core-services host instance used in managed side
 *
 * @internal
 */
export interface CoreServicesShimHost extends Logger {
    directoryExists(directoryName: string): boolean;
    fileExists(fileName: string): boolean;
    getCurrentDirectory(): string;
    getDirectories(path: string): string;
    /**
     * Returns a JSON-encoded value of the type: string[]
     *
     * @param exclude A JSON encoded string[] containing the paths to exclude
     *  when enumerating the directory.
     */
    readDirectory(rootDir: string, extension: string, basePaths?: string, excludeEx?: string, includeFileEx?: string, includeDirEx?: string, depth?: number): string;
    /**
     * Read arbitrary text files on disk, i.e. when resolution procedure needs the content of 'package.json' to determine location of bundled typings for node modules
     */
    readFile(fileName: string): string | undefined;
    realpath?(path: string): string;
    trace(s: string): void;
    useCaseSensitiveFileNames?(): boolean;
}
/** @internal */
export interface ShimsFileReference {
    path: string;
    position: number;
    length: number;
}
/**
 * Public interface of a language service instance shim.
 *
 * @internal
 */
export interface ShimFactory {
    registerShim(shim: Shim): void;
    unregisterShim(shim: Shim): void;
}
/** @internal */
export interface Shim {
    dispose(_dummy: {}): void;
}
/** @internal */
export interface LanguageServiceShim extends Shim {
    languageService: LanguageService;
    dispose(_dummy: {}): void;
    refresh(throwOnError: boolean): void;
    cleanupSemanticCache(): void;
    getSyntacticDiagnostics(fileName: string): string;
    getSemanticDiagnostics(fileName: string): string;
    getSuggestionDiagnostics(fileName: string): string;
    getCompilerOptionsDiagnostics(): string;
    getSyntacticClassifications(fileName: string, start: number, length: number): string;
    getSemanticClassifications(fileName: string, start: number, length: number, format?: SemanticClassificationFormat): string;
    getEncodedSyntacticClassifications(fileName: string, start: number, length: number): string;
    getEncodedSemanticClassifications(fileName: string, start: number, length: number, format?: SemanticClassificationFormat): string;
    getCompletionsAtPosition(fileName: string, position: number, preferences: UserPreferences | undefined, formattingSettings: FormatCodeSettings | undefined): string;
    getCompletionEntryDetails(fileName: string, position: number, entryName: string, formatOptions: string | undefined, source: string | undefined, preferences: UserPreferences | undefined, data: CompletionEntryData | undefined): string;
    getQuickInfoAtPosition(fileName: string, position: number): string;
    getNameOrDottedNameSpan(fileName: string, startPos: number, endPos: number): string;
    getBreakpointStatementAtPosition(fileName: string, position: number): string;
    getSignatureHelpItems(fileName: string, position: number, options: SignatureHelpItemsOptions | undefined): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { canRename: boolean, localizedErrorMessage: string, displayName: string, fullDisplayName: string, kind: string, kindModifiers: string, triggerSpan: { start; length } }
     */
    getRenameInfo(fileName: string, position: number, preferences: UserPreferences): string;
    getSmartSelectionRange(fileName: string, position: number): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { fileName: string, textSpan: { start: number, length: number } }[]
     */
    findRenameLocations(fileName: string, position: number, findInStrings: boolean, findInComments: boolean, preferences?: UserPreferences | boolean): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { fileName: string; textSpan: { start: number; length: number}; kind: string; name: string; containerKind: string; containerName: string }
     *
     * Or undefined value if no definition can be found.
     */
    getDefinitionAtPosition(fileName: string, position: number): string;
    getDefinitionAndBoundSpan(fileName: string, position: number): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { fileName: string; textSpan: { start: number; length: number}; kind: string; name: string; containerKind: string; containerName: string }
     *
     * Or undefined value if no definition can be found.
     */
    getTypeDefinitionAtPosition(fileName: string, position: number): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { fileName: string; textSpan: { start: number; length: number}; }[]
     */
    getImplementationAtPosition(fileName: string, position: number): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { fileName: string; textSpan: { start: number; length: number}; isWriteAccess: boolean, isDefinition?: boolean }[]
     */
    getReferencesAtPosition(fileName: string, position: number): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { definition: <encoded>; references: <encoded>[] }[]
     */
    findReferences(fileName: string, position: number): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { fileName: string; textSpan: { start: number; length: number}; isWriteAccess: boolean, isDefinition?: boolean }[]
     */
    getFileReferences(fileName: string): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { fileName: string; highlights: { start: number; length: number }[] }[]
     *
     * @param fileToSearch A JSON encoded string[] containing the file names that should be
     *  considered when searching.
     */
    getDocumentHighlights(fileName: string, position: number, filesToSearch: string): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { name: string; kind: string; kindModifiers: string; containerName: string; containerKind: string; matchKind: string; fileName: string; textSpan: { start: number; length: number}; } [] = [];
     */
    getNavigateToItems(searchValue: string, maxResultCount?: number, fileName?: string): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { text: string; kind: string; kindModifiers: string; bolded: boolean; grayed: boolean; indent: number; spans: { start: number; length: number; }[]; childItems: <recursive use of this type>[] } [] = [];
     */
    getNavigationBarItems(fileName: string): string;
    /** Returns a JSON-encoded value of the type ts.NavigationTree. */
    getNavigationTree(fileName: string): string;
    /**
     * Returns a JSON-encoded value of the type:
     * { textSpan: { start: number, length: number }; hintSpan: { start: number, length: number }; bannerText: string; autoCollapse: boolean } [] = [];
     */
    getOutliningSpans(fileName: string): string;
    getTodoComments(fileName: string, todoCommentDescriptors: string): string;
    getBraceMatchingAtPosition(fileName: string, position: number): string;
    getIndentationAtPosition(fileName: string, position: number, options: string): string;
    getFormattingEditsForRange(fileName: string, start: number, end: number, options: string): string;
    getFormattingEditsForDocument(fileName: string, options: string): string;
    getFormattingEditsAfterKeystroke(fileName: string, position: number, key: string, options: string): string;
    /**
     * Returns JSON-encoded value of the type TextInsertion.
     */
    getDocCommentTemplateAtPosition(fileName: string, position: number, options?: DocCommentTemplateOptions, formatOptions?: FormatCodeSettings): string;
    /**
     * Returns JSON-encoded boolean to indicate whether we should support brace location
     * at the current position.
     * E.g. we don't want brace completion inside string-literals, comments, etc.
     */
    isValidBraceCompletionAtPosition(fileName: string, position: number, openingBrace: number): string;
    /**
     * Returns a JSON-encoded TextSpan | undefined indicating the range of the enclosing comment, if it exists.
     */
    getSpanOfEnclosingComment(fileName: string, position: number, onlyMultiLine: boolean): string;
    prepareCallHierarchy(fileName: string, position: number): string;
    provideCallHierarchyIncomingCalls(fileName: string, position: number): string;
    provideCallHierarchyOutgoingCalls(fileName: string, position: number): string;
    provideInlayHints(fileName: string, span: TextSpan, preference: UserPreferences | undefined): string;
    getEmitOutput(fileName: string): string;
    getEmitOutputObject(fileName: string): EmitOutput;
    toggleLineComment(fileName: string, textChange: TextRange): string;
    toggleMultilineComment(fileName: string, textChange: TextRange): string;
    commentSelection(fileName: string, textChange: TextRange): string;
    uncommentSelection(fileName: string, textChange: TextRange): string;
}
/** @internal */
export interface ClassifierShim extends Shim {
    getEncodedLexicalClassifications(text: string, lexState: EndOfLineState, syntacticClassifierAbsent?: boolean): string;
    getClassificationsForLine(text: string, lexState: EndOfLineState, syntacticClassifierAbsent?: boolean): string;
}
/** @internal */
export interface CoreServicesShim extends Shim {
    getAutomaticTypeDirectiveNames(compilerOptionsJson: string): string;
    getPreProcessedFileInfo(fileName: string, sourceText: IScriptSnapshot): string;
    getTSConfigFileInfo(fileName: string, sourceText: IScriptSnapshot): string;
    getDefaultCompilationSettings(): string;
    discoverTypings(discoverTypingsJson: string): string;
}
/** @internal */
export declare class LanguageServiceShimHostAdapter implements LanguageServiceHost {
    private shimHost;
    private loggingEnabled;
    private tracingEnabled;
    resolveModuleNames: ((moduleName: string[], containingFile: string) => (ResolvedModuleFull | undefined)[]) | undefined;
    resolveTypeReferenceDirectives: ((typeDirectiveNames: string[] | readonly FileReference[], containingFile: string) => (ResolvedTypeReferenceDirective | undefined)[]) | undefined;
    directoryExists: ((directoryName: string) => boolean) | undefined;
    constructor(shimHost: LanguageServiceShimHost);
    log(s: string): void;
    trace(s: string): void;
    error(s: string): void;
    getProjectVersion(): string;
    getTypeRootsVersion(): number;
    useCaseSensitiveFileNames(): boolean;
    getCompilationSettings(): CompilerOptions;
    getScriptFileNames(): string[];
    getScriptSnapshot(fileName: string): IScriptSnapshot | undefined;
    getScriptKind(fileName: string): ScriptKind;
    getScriptVersion(fileName: string): string;
    getLocalizedDiagnosticMessages(): any;
    getCancellationToken(): HostCancellationToken;
    getCurrentDirectory(): string;
    getDirectories(path: string): string[];
    getDefaultLibFileName(options: CompilerOptions): string;
    readDirectory(path: string, extensions?: readonly string[], exclude?: string[], include?: string[], depth?: number): string[];
    readFile(path: string, encoding?: string): string | undefined;
    fileExists(path: string): boolean;
}
/** @internal */
export declare class CoreServicesShimHostAdapter implements ParseConfigHost, ModuleResolutionHost, JsTyping.TypingResolutionHost {
    private shimHost;
    directoryExists: (directoryName: string) => boolean;
    realpath: (path: string) => string;
    useCaseSensitiveFileNames: boolean;
    constructor(shimHost: CoreServicesShimHost);
    readDirectory(rootDir: string, extensions: readonly string[], exclude: readonly string[], include: readonly string[], depth?: number): string[];
    fileExists(fileName: string): boolean;
    readFile(fileName: string): string | undefined;
    getDirectories(path: string): string[];
}
/** @internal */
export interface RealizedDiagnostic {
    message: string;
    start: number;
    length: number;
    category: string;
    code: number;
    reportsUnnecessary?: {};
    reportsDeprecated?: {};
}
/** @internal */
export declare function realizeDiagnostics(diagnostics: readonly Diagnostic[], newLine: string): RealizedDiagnostic[];
/** @internal */
export declare class TypeScriptServicesFactory implements ShimFactory {
    private _shims;
    private documentRegistry;
    getServicesVersion(): string;
    createLanguageServiceShim(host: LanguageServiceShimHost): LanguageServiceShim;
    createClassifierShim(logger: Logger): ClassifierShim;
    createCoreServicesShim(host: CoreServicesShimHost): CoreServicesShim;
    close(): void;
    registerShim(shim: Shim): void;
    unregisterShim(shim: Shim): void;
}
//# sourceMappingURL=shims.d.ts.map