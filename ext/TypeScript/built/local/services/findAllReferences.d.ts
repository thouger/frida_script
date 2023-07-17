import { BinaryExpression, CallExpression, CancellationToken, FileReference, ForInOrOfStatement, HighlightSpan, Identifier, ImplementationLocation, NamedDeclaration, Node, Program, QuotePreference, ReferencedSymbol, ReferenceEntry, RenameLocation, SemanticMeaning, SignatureDeclaration, SourceFile, StringLiteralLike, Symbol, TextSpan, TypeChecker } from "./_namespaces/ts";
/** @internal */
export interface SymbolAndEntries {
    readonly definition: Definition | undefined;
    readonly references: readonly Entry[];
}
/** @internal */
export declare const enum DefinitionKind {
    Symbol = 0,
    Label = 1,
    Keyword = 2,
    This = 3,
    String = 4,
    TripleSlashReference = 5
}
/** @internal */
export type Definition = {
    readonly type: DefinitionKind.Symbol;
    readonly symbol: Symbol;
} | {
    readonly type: DefinitionKind.Label;
    readonly node: Identifier;
} | {
    readonly type: DefinitionKind.Keyword;
    readonly node: Node;
} | {
    readonly type: DefinitionKind.This;
    readonly node: Node;
} | {
    readonly type: DefinitionKind.String;
    readonly node: StringLiteralLike;
} | {
    readonly type: DefinitionKind.TripleSlashReference;
    readonly reference: FileReference;
    readonly file: SourceFile;
};
/** @internal */
export declare const enum EntryKind {
    Span = 0,
    Node = 1,
    StringLiteral = 2,
    SearchedLocalFoundProperty = 3,
    SearchedPropertyFoundLocal = 4
}
/** @internal */
export type NodeEntryKind = EntryKind.Node | EntryKind.StringLiteral | EntryKind.SearchedLocalFoundProperty | EntryKind.SearchedPropertyFoundLocal;
/** @internal */
export type Entry = NodeEntry | SpanEntry;
/** @internal */
export interface ContextWithStartAndEndNode {
    start: Node;
    end: Node;
}
/** @internal */
export type ContextNode = Node | ContextWithStartAndEndNode;
/** @internal */
export interface NodeEntry {
    readonly kind: NodeEntryKind;
    readonly node: Node;
    readonly context?: ContextNode;
}
/** @internal */
export interface SpanEntry {
    readonly kind: EntryKind.Span;
    readonly fileName: string;
    readonly textSpan: TextSpan;
}
/** @internal */
export declare function nodeEntry(node: Node, kind?: NodeEntryKind): NodeEntry;
/** @internal */
export declare function isContextWithStartAndEndNode(node: ContextNode): node is ContextWithStartAndEndNode;
/** @internal */
export declare function getContextNode(node: NamedDeclaration | BinaryExpression | ForInOrOfStatement | undefined): ContextNode | undefined;
/** @internal */
export declare function toContextSpan(textSpan: TextSpan, sourceFile: SourceFile, context?: ContextNode): {
    contextSpan: TextSpan;
} | undefined;
/** @internal */
export declare const enum FindReferencesUse {
    /**
     * When searching for references to a symbol, the location will not be adjusted (this is the default behavior when not specified).
     */
    Other = 0,
    /**
     * When searching for references to a symbol, the location will be adjusted if the cursor was on a keyword.
     */
    References = 1,
    /**
     * When searching for references to a symbol, the location will be adjusted if the cursor was on a keyword.
     * Unlike `References`, the location will only be adjusted keyword belonged to a declaration with a valid name.
     * If set, we will find fewer references -- if it is referenced by several different names, we still only find references for the original name.
     */
    Rename = 2
}
/** @internal */
export interface Options {
    readonly findInStrings?: boolean;
    readonly findInComments?: boolean;
    readonly use?: FindReferencesUse;
    /** True if we are searching for implementations. We will have a different method of adding references if so. */
    readonly implementations?: boolean;
    /**
     * True to opt in for enhanced renaming of shorthand properties and import/export specifiers.
     * The options controls the behavior for the whole rename operation; it cannot be changed on a per-file basis.
     * Default is false for backwards compatibility.
     */
    readonly providePrefixAndSuffixTextForRename?: boolean;
}
/** @internal */
export declare function findReferencedSymbols(program: Program, cancellationToken: CancellationToken, sourceFiles: readonly SourceFile[], sourceFile: SourceFile, position: number): ReferencedSymbol[] | undefined;
/** @internal */
export declare function getImplementationsAtPosition(program: Program, cancellationToken: CancellationToken, sourceFiles: readonly SourceFile[], sourceFile: SourceFile, position: number): ImplementationLocation[] | undefined;
/** @internal */
export declare function findReferenceOrRenameEntries<T>(program: Program, cancellationToken: CancellationToken, sourceFiles: readonly SourceFile[], node: Node, position: number, options: Options | undefined, convertEntry: ToReferenceOrRenameEntry<T>): T[] | undefined;
/** @internal */
export type ToReferenceOrRenameEntry<T> = (entry: Entry, originalNode: Node, checker: TypeChecker) => T;
/** @internal */
export declare function getReferenceEntriesForNode(position: number, node: Node, program: Program, sourceFiles: readonly SourceFile[], cancellationToken: CancellationToken, options?: Options, sourceFilesSet?: ReadonlySet<string>): readonly Entry[] | undefined;
/** @internal */
export declare function toRenameLocation(entry: Entry, originalNode: Node, checker: TypeChecker, providePrefixAndSuffixText: boolean, quotePreference: QuotePreference): RenameLocation;
/** @internal */
export declare function toReferenceEntry(entry: Entry): ReferenceEntry;
/** @internal */
export declare function toHighlightSpan(entry: Entry): {
    fileName: string;
    span: HighlightSpan;
};
/** @internal */
export declare function getTextSpanOfEntry(entry: Entry): TextSpan;
/**
 * Whether a reference, `node`, is a definition of the `target` symbol
 *
 * @internal
 */
export declare function isDeclarationOfSymbol(node: Node, target: Symbol | undefined): boolean;
/**
 * Encapsulates the core find-all-references algorithm.
 *
 * @internal
 */
export declare namespace Core {
    /** Core find-all-references algorithm. Handles special cases before delegating to `getReferencedSymbolsForSymbol`. */
    function getReferencedSymbolsForNode(position: number, node: Node, program: Program, sourceFiles: readonly SourceFile[], cancellationToken: CancellationToken, options?: Options, sourceFilesSet?: ReadonlySet<string>): readonly SymbolAndEntries[] | undefined;
    function getAdjustedNode(node: Node, options: Options): Node;
    function getReferencesForFileName(fileName: string, program: Program, sourceFiles: readonly SourceFile[], sourceFilesSet?: ReadonlySet<string>): readonly Entry[];
    function eachExportReference(sourceFiles: readonly SourceFile[], checker: TypeChecker, cancellationToken: CancellationToken | undefined, exportSymbol: Symbol, exportingModuleSymbol: Symbol, exportName: string, isDefaultExport: boolean, cb: (ref: Identifier) => void): void;
    /** Used as a quick check for whether a symbol is used at all in a file (besides its definition). */
    function isSymbolReferencedInFile(definition: Identifier, checker: TypeChecker, sourceFile: SourceFile, searchContainer?: Node): boolean;
    function eachSymbolReferenceInFile<T>(definition: Identifier, checker: TypeChecker, sourceFile: SourceFile, cb: (token: Identifier) => T, searchContainer?: Node): T | undefined;
    function getTopMostDeclarationNamesInFile(declarationName: string, sourceFile: SourceFile): readonly Node[];
    function someSignatureUsage(signature: SignatureDeclaration, sourceFiles: readonly SourceFile[], checker: TypeChecker, cb: (name: Identifier, call?: CallExpression) => boolean): boolean;
    /**
     * Given an initial searchMeaning, extracted from a location, widen the search scope based on the declarations
     * of the corresponding symbol. e.g. if we are searching for "Foo" in value position, but "Foo" references a class
     * then we need to widen the search to include type positions as well.
     * On the contrary, if we are searching for "Bar" in type position and we trace bar to an interface, and an uninstantiated
     * module, we want to keep the search limited to only types, as the two declarations (interface and uninstantiated module)
     * do not intersect in any of the three spaces.
     */
    function getIntersectingMeaningFromDeclarations(node: Node, symbol: Symbol): SemanticMeaning;
    function getReferenceEntriesForShorthandPropertyAssignment(node: Node, checker: TypeChecker, addReference: (node: Node) => void): void;
}
//# sourceMappingURL=findAllReferences.d.ts.map