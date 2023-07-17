import { __String, AnyImportOrRequireStatement, BindingElement, BreakOrContinueStatement, CallExpression, CaseClause, CommentKind, CommentRange, CompilerOptions, ContextFlags, Declaration, DefaultClause, Diagnostic, DiagnosticAndArguments, DiagnosticMessage, DiagnosticWithLocation, DisplayPartsSymbolWriter, DocumentPosition, DocumentSpan, EqualityOperator, Expression, FileTextChanges, FormatCodeSettings, formatting, FormattingHost, Identifier, ImportClause, ImportDeclaration, ImportSpecifier, IScriptSnapshot, JSDocLink, JSDocLinkCode, JSDocLinkDisplayPart, JSDocLinkPlain, JsxEmit, LanguageServiceHost, Modifier, ModifierFlags, ModuleResolutionKind, ModuleSpecifierResolutionHost, NewLineKind, Node, NodeArray, NoSubstitutionTemplateLiteral, NumericLiteral, Program, ProjectPackageJsonInfo, PropertyName, PseudoBigInt, RefactorContext, Scanner, ScriptElementKind, ScriptKind, ScriptTarget, Signature, SourceFile, SourceFileLike, SourceMapper, StringLiteral, StringLiteralLike, Symbol, SymbolDisplayPart, SymbolDisplayPartKind, SymbolFlags, SymbolFormatFlags, SymbolTracker, SyntaxKind, SyntaxList, TaggedTemplateExpression, TemplateExpression, TemplateLiteralToken, TextChange, textChanges, TextRange, TextSpan, Token, Type, TypeChecker, TypeFormatFlags, TypeNode, UserPreferences } from "./_namespaces/ts";
/** @internal */
export declare const scanner: Scanner;
/** @internal */
export declare const enum SemanticMeaning {
    None = 0,
    Value = 1,
    Type = 2,
    Namespace = 4,
    All = 7
}
/** @internal */
export declare function getMeaningFromDeclaration(node: Node): SemanticMeaning;
/** @internal */
export declare function getMeaningFromLocation(node: Node): SemanticMeaning;
/** @internal */
export declare function isInRightSideOfInternalImportEqualsDeclaration(node: Node): boolean;
/** @internal */
export declare function isCallExpressionTarget(node: Node, includeElementAccess?: boolean, skipPastOuterExpressions?: boolean): boolean;
/** @internal */
export declare function isNewExpressionTarget(node: Node, includeElementAccess?: boolean, skipPastOuterExpressions?: boolean): boolean;
/** @internal */
export declare function isCallOrNewExpressionTarget(node: Node, includeElementAccess?: boolean, skipPastOuterExpressions?: boolean): boolean;
/** @internal */
export declare function isTaggedTemplateTag(node: Node, includeElementAccess?: boolean, skipPastOuterExpressions?: boolean): boolean;
/** @internal */
export declare function isDecoratorTarget(node: Node, includeElementAccess?: boolean, skipPastOuterExpressions?: boolean): boolean;
/** @internal */
export declare function isJsxOpeningLikeElementTagName(node: Node, includeElementAccess?: boolean, skipPastOuterExpressions?: boolean): boolean;
/** @internal */
export declare function climbPastPropertyAccess(node: Node): Node;
/** @internal */
export declare function climbPastPropertyOrElementAccess(node: Node): Node;
/** @internal */
export declare function getTargetLabel(referenceNode: Node, labelName: string): Identifier | undefined;
/** @internal */
export declare function hasPropertyAccessExpressionWithName(node: CallExpression, funcName: string): boolean;
/** @internal */
export declare function isJumpStatementTarget(node: Node): node is Identifier & {
    parent: BreakOrContinueStatement;
};
/** @internal */
export declare function isLabelOfLabeledStatement(node: Node): node is Identifier;
/** @internal */
export declare function isLabelName(node: Node): boolean;
/** @internal */
export declare function isTagName(node: Node): boolean;
/** @internal */
export declare function isRightSideOfQualifiedName(node: Node): boolean;
/** @internal */
export declare function isRightSideOfPropertyAccess(node: Node): boolean;
/** @internal */
export declare function isArgumentExpressionOfElementAccess(node: Node): boolean;
/** @internal */
export declare function isNameOfModuleDeclaration(node: Node): boolean;
/** @internal */
export declare function isNameOfFunctionDeclaration(node: Node): boolean;
/** @internal */
export declare function isLiteralNameOfPropertyDeclarationOrIndexAccess(node: StringLiteral | NumericLiteral | NoSubstitutionTemplateLiteral): boolean;
/** @internal */
export declare function isExpressionOfExternalModuleImportEqualsDeclaration(node: Node): boolean;
/** @internal */
export declare function getContainerNode(node: Node): Declaration | undefined;
/** @internal */
export declare function getNodeKind(node: Node): ScriptElementKind;
/** @internal */
export declare function isThis(node: Node): boolean;
/** @internal */
export interface ListItemInfo {
    listItemIndex: number;
    list: Node;
}
/** @internal */
export declare function getLineStartPositionForPosition(position: number, sourceFile: SourceFileLike): number;
/** @internal */
export declare function rangeContainsRange(r1: TextRange, r2: TextRange): boolean;
/** @internal */
export declare function rangeContainsRangeExclusive(r1: TextRange, r2: TextRange): boolean;
/** @internal */
export declare function rangeContainsPosition(r: TextRange, pos: number): boolean;
/** @internal */
export declare function rangeContainsPositionExclusive(r: TextRange, pos: number): boolean;
/** @internal */
export declare function startEndContainsRange(start: number, end: number, range: TextRange): boolean;
/** @internal */
export declare function rangeContainsStartEnd(range: TextRange, start: number, end: number): boolean;
/** @internal */
export declare function rangeOverlapsWithStartEnd(r1: TextRange, start: number, end: number): boolean;
/** @internal */
export declare function nodeOverlapsWithStartEnd(node: Node, sourceFile: SourceFile, start: number, end: number): boolean;
/** @internal */
export declare function startEndOverlapsWithStartEnd(start1: number, end1: number, start2: number, end2: number): boolean;
/**
 * Assumes `candidate.start <= position` holds.
 *
 * @internal
 */
export declare function positionBelongsToNode(candidate: Node, position: number, sourceFile: SourceFile): boolean;
/** @internal */
export declare function findListItemInfo(node: Node): ListItemInfo | undefined;
/** @internal */
export declare function hasChildOfKind(n: Node, kind: SyntaxKind, sourceFile: SourceFile): boolean;
/** @internal */
export declare function findChildOfKind<T extends Node>(n: Node, kind: T["kind"], sourceFile: SourceFileLike): T | undefined;
/** @internal */
export declare function findContainingList(node: Node): SyntaxList | undefined;
/** @internal */
export declare function getContextualTypeFromParentOrAncestorTypeNode(node: Expression, checker: TypeChecker): Type | undefined;
/**
 * Adjusts the location used for "find references" and "go to definition" when the cursor was not
 * on a property name.
 *
 * @internal
 */
export declare function getAdjustedReferenceLocation(node: Node): Node;
/**
 * Adjusts the location used for "rename" when the cursor was not on a property name.
 *
 * @internal
 */
export declare function getAdjustedRenameLocation(node: Node): Node;
/**
 * Gets the token whose text has range [start, end) and
 * position >= start and (position < end or (position === end && token is literal or keyword or identifier))
 *
 * @internal
 */
export declare function getTouchingPropertyName(sourceFile: SourceFile, position: number): Node;
/**
 * Returns the token if position is in [start, end).
 * If position === end, returns the preceding token if includeItemAtEndPosition(previousToken) === true
 *
 * @internal
 */
export declare function getTouchingToken(sourceFile: SourceFile, position: number, includePrecedingTokenAtEndPosition?: (n: Node) => boolean): Node;
/**
 * Returns a token if position is in [start-of-leading-trivia, end)
 *
 * @internal
 */
export declare function getTokenAtPosition(sourceFile: SourceFile, position: number): Node;
/**
 * Returns the first token where position is in [start, end),
 * excluding `JsxText` tokens containing only whitespace.
 *
 * @internal
 */
export declare function findFirstNonJsxWhitespaceToken(sourceFile: SourceFile, position: number): Node | undefined;
/**
 * The token on the left of the position is the token that strictly includes the position
 * or sits to the left of the cursor if it is on a boundary. For example
 *
 *   fo|o               -> will return foo
 *   foo <comment> |bar -> will return foo
 *
 *
 * @internal
 */
export declare function findTokenOnLeftOfPosition(file: SourceFile, position: number): Node | undefined;
/** @internal */
export declare function findNextToken(previousToken: Node, parent: Node, sourceFile: SourceFileLike): Node | undefined;
/**
 * Finds the rightmost token satisfying `token.end <= position`,
 * excluding `JsxText` tokens containing only whitespace.
 *
 * @internal
 */
export declare function findPrecedingToken(position: number, sourceFile: SourceFileLike, startNode: Node, excludeJsdoc?: boolean): Node | undefined;
/** @internal */
export declare function findPrecedingToken(position: number, sourceFile: SourceFile, startNode?: Node, excludeJsdoc?: boolean): Node | undefined;
/** @internal */
export declare function isInString(sourceFile: SourceFile, position: number, previousToken?: Node | undefined): boolean;
/**
 *
 * @internal
 */
export declare function isInsideJsxElementOrAttribute(sourceFile: SourceFile, position: number): boolean;
/** @internal */
export declare function isInTemplateString(sourceFile: SourceFile, position: number): boolean;
/** @internal */
export declare function isInJSXText(sourceFile: SourceFile, position: number): boolean;
/** @internal */
export declare function isInsideJsxElement(sourceFile: SourceFile, position: number): boolean;
/** @internal */
export declare function findPrecedingMatchingToken(token: Node, matchingTokenKind: SyntaxKind.OpenBraceToken | SyntaxKind.OpenParenToken | SyntaxKind.OpenBracketToken, sourceFile: SourceFile): Node | undefined;
/** @internal */
export declare function removeOptionality(type: Type, isOptionalExpression: boolean, isOptionalChain: boolean): Type;
/** @internal */
export declare function isPossiblyTypeArgumentPosition(token: Node, sourceFile: SourceFile, checker: TypeChecker): boolean;
/** @internal */
export declare function getPossibleGenericSignatures(called: Expression, typeArgumentCount: number, checker: TypeChecker): readonly Signature[];
/** @internal */
export interface PossibleTypeArgumentInfo {
    readonly called: Identifier;
    readonly nTypeArguments: number;
}
/** @internal */
export interface PossibleProgramFileInfo {
    ProgramFiles?: string[];
}
/** @internal */
export declare function getPossibleTypeArgumentsInfo(tokenIn: Node | undefined, sourceFile: SourceFile): PossibleTypeArgumentInfo | undefined;
/**
 * Returns true if the cursor at position in sourceFile is within a comment.
 *
 * @param tokenAtPosition Must equal `getTokenAtPosition(sourceFile, position)`
 * @param predicate Additional predicate to test on the comment range.
 *
 * @internal
 */
export declare function isInComment(sourceFile: SourceFile, position: number, tokenAtPosition?: Node): CommentRange | undefined;
/** @internal */
export declare function hasDocComment(sourceFile: SourceFile, position: number): boolean;
/** @internal */
export declare function getNodeModifiers(node: Node, excludeFlags?: ModifierFlags): string;
/** @internal */
export declare function getTypeArgumentOrTypeParameterList(node: Node): NodeArray<Node> | undefined;
/** @internal */
export declare function isComment(kind: SyntaxKind): boolean;
/** @internal */
export declare function isStringOrRegularExpressionOrTemplateLiteral(kind: SyntaxKind): boolean;
/** @internal */
export declare function isStringAndEmptyAnonymousObjectIntersection(type: Type): boolean;
/** @internal */
export declare function isInsideTemplateLiteral(node: TemplateLiteralToken, position: number, sourceFile: SourceFile): boolean;
/** @internal */
export declare function isAccessibilityModifier(kind: SyntaxKind): boolean;
/** @internal */
export declare function cloneCompilerOptions(options: CompilerOptions): CompilerOptions;
/** @internal */
export declare function isArrayLiteralOrObjectLiteralDestructuringPattern(node: Node): boolean;
/** @internal */
export declare function isInReferenceComment(sourceFile: SourceFile, position: number): boolean;
/** @internal */
export declare function isInNonReferenceComment(sourceFile: SourceFile, position: number): boolean;
/** @internal */
export declare function getReplacementSpanForContextToken(contextToken: Node | undefined): TextSpan | undefined;
/** @internal */
export declare function createTextSpanFromNode(node: Node, sourceFile?: SourceFile, endNode?: Node): TextSpan;
/** @internal */
export declare function createTextSpanFromStringLiteralLikeContent(node: StringLiteralLike): TextSpan | undefined;
/** @internal */
export declare function createTextRangeFromNode(node: Node, sourceFile: SourceFile): TextRange;
/** @internal */
export declare function createTextSpanFromRange(range: TextRange): TextSpan;
/** @internal */
export declare function createTextRangeFromSpan(span: TextSpan): TextRange;
/** @internal */
export declare function createTextChangeFromStartLength(start: number, length: number, newText: string): TextChange;
/** @internal */
export declare function createTextChange(span: TextSpan, newText: string): TextChange;
/** @internal */
export declare const typeKeywords: readonly SyntaxKind[];
/** @internal */
export declare function isTypeKeyword(kind: SyntaxKind): boolean;
/** @internal */
export declare function isTypeKeywordToken(node: Node): node is Token<SyntaxKind.TypeKeyword>;
/** @internal */
export declare function isTypeKeywordTokenOrIdentifier(node: Node): boolean;
/**
 * True if the symbol is for an external module, as opposed to a namespace.
 *
 * @internal
 */
export declare function isExternalModuleSymbol(moduleSymbol: Symbol): boolean;
/**
 * Returns `true` the first time it encounters a node and `false` afterwards.
 *
 * @internal
 */
export type NodeSeenTracker<T = Node> = (node: T) => boolean;
/** @internal */
export declare function nodeSeenTracker<T extends Node>(): NodeSeenTracker<T>;
/** @internal */
export declare function getSnapshotText(snap: IScriptSnapshot): string;
/** @internal */
export declare function repeatString(str: string, count: number): string;
/** @internal */
export declare function skipConstraint(type: Type): Type;
/** @internal */
export declare function getNameFromPropertyName(name: PropertyName): string | undefined;
/** @internal */
export declare function programContainsModules(program: Program): boolean;
/** @internal */
export declare function programContainsEsModules(program: Program): boolean;
/** @internal */
export declare function compilerOptionsIndicateEsModules(compilerOptions: CompilerOptions): boolean;
/** @internal */
export declare function createModuleSpecifierResolutionHost(program: Program, host: LanguageServiceHost): ModuleSpecifierResolutionHost;
/** @internal */
export declare function getModuleSpecifierResolverHost(program: Program, host: LanguageServiceHost): SymbolTracker["moduleResolverHost"];
/** @internal */
export declare function moduleResolutionUsesNodeModules(moduleResolution: ModuleResolutionKind): boolean;
/** @internal */
export declare function makeImportIfNecessary(defaultImport: Identifier | undefined, namedImports: readonly ImportSpecifier[] | undefined, moduleSpecifier: string, quotePreference: QuotePreference): ImportDeclaration | undefined;
/** @internal */
export declare function makeImport(defaultImport: Identifier | undefined, namedImports: readonly ImportSpecifier[] | undefined, moduleSpecifier: string | Expression, quotePreference: QuotePreference, isTypeOnly?: boolean): ImportDeclaration;
/** @internal */
export declare function makeStringLiteral(text: string, quotePreference: QuotePreference): StringLiteral;
/** @internal */
export declare const enum QuotePreference {
    Single = 0,
    Double = 1
}
/** @internal */
export declare function quotePreferenceFromString(str: StringLiteral, sourceFile: SourceFile): QuotePreference;
/** @internal */
export declare function getQuotePreference(sourceFile: SourceFile, preferences: UserPreferences): QuotePreference;
/** @internal */
export declare function getQuoteFromPreference(qp: QuotePreference): string;
/** @internal */
export declare function symbolNameNoDefault(symbol: Symbol): string | undefined;
/** @internal */
export declare function symbolEscapedNameNoDefault(symbol: Symbol): __String | undefined;
/** @internal */
export declare function isModuleSpecifierLike(node: Node): node is StringLiteralLike;
/** @internal */
export type ObjectBindingElementWithoutPropertyName = BindingElement & {
    name: Identifier;
};
/** @internal */
export declare function isObjectBindingElementWithoutPropertyName(bindingElement: Node): bindingElement is ObjectBindingElementWithoutPropertyName;
/** @internal */
export declare function getPropertySymbolFromBindingElement(checker: TypeChecker, bindingElement: ObjectBindingElementWithoutPropertyName): Symbol | undefined;
/** @internal */
export declare function getParentNodeInSpan(node: Node | undefined, file: SourceFile, span: TextSpan): Node | undefined;
/** @internal */
export declare function findModifier(node: Node, kind: Modifier["kind"]): Modifier | undefined;
/** @internal */
export declare function insertImports(changes: textChanges.ChangeTracker, sourceFile: SourceFile, imports: AnyImportOrRequireStatement | readonly AnyImportOrRequireStatement[], blankLineBetween: boolean, preferences: UserPreferences): void;
/** @internal */
export declare function getTypeKeywordOfTypeOnlyImport(importClause: ImportClause, sourceFile: SourceFile): Token<SyntaxKind.TypeKeyword>;
/** @internal */
export declare function textSpansEqual(a: TextSpan | undefined, b: TextSpan | undefined): boolean;
/** @internal */
export declare function documentSpansEqual(a: DocumentSpan, b: DocumentSpan): boolean;
/**
 * Iterates through 'array' by index and performs the callback on each element of array until the callback
 * returns a truthy value, then returns that value.
 * If no such value is found, the callback is applied to each element of array and undefined is returned.
 *
 * @internal
 */
export declare function forEachUnique<T, U>(array: readonly T[] | undefined, callback: (element: T, index: number) => U): U | undefined;
/** @internal */
export declare function isTextWhiteSpaceLike(text: string, startPos: number, endPos: number): boolean;
/** @internal */
export declare function getMappedLocation(location: DocumentPosition, sourceMapper: SourceMapper, fileExists: ((path: string) => boolean) | undefined): DocumentPosition | undefined;
/** @internal */
export declare function getMappedDocumentSpan(documentSpan: DocumentSpan, sourceMapper: SourceMapper, fileExists?: (path: string) => boolean): DocumentSpan | undefined;
/** @internal */
export declare function getMappedContextSpan(documentSpan: DocumentSpan, sourceMapper: SourceMapper, fileExists?: (path: string) => boolean): TextSpan | undefined;
/** @internal */
export declare function isFirstDeclarationOfSymbolParameter(symbol: Symbol): boolean;
/** @internal */
export declare function symbolPart(text: string, symbol: Symbol): SymbolDisplayPart;
/** @internal */
export declare function displayPart(text: string, kind: SymbolDisplayPartKind): SymbolDisplayPart;
/** @internal */
export declare function spacePart(): SymbolDisplayPart;
/** @internal */
export declare function keywordPart(kind: SyntaxKind): SymbolDisplayPart;
/** @internal */
export declare function punctuationPart(kind: SyntaxKind): SymbolDisplayPart;
/** @internal */
export declare function operatorPart(kind: SyntaxKind): SymbolDisplayPart;
/** @internal */
export declare function parameterNamePart(text: string): SymbolDisplayPart;
/** @internal */
export declare function propertyNamePart(text: string): SymbolDisplayPart;
/** @internal */
export declare function textOrKeywordPart(text: string): SymbolDisplayPart;
/** @internal */
export declare function textPart(text: string): SymbolDisplayPart;
/** @internal */
export declare function typeAliasNamePart(text: string): SymbolDisplayPart;
/** @internal */
export declare function typeParameterNamePart(text: string): SymbolDisplayPart;
/** @internal */
export declare function linkTextPart(text: string): SymbolDisplayPart;
/** @internal */
export declare function linkNamePart(text: string, target: Declaration): JSDocLinkDisplayPart;
/** @internal */
export declare function linkPart(text: string): SymbolDisplayPart;
/** @internal */
export declare function buildLinkParts(link: JSDocLink | JSDocLinkCode | JSDocLinkPlain, checker?: TypeChecker): SymbolDisplayPart[];
/**
 * The default is LF.
 *
 * @internal
 */
export declare function getNewLineOrDefaultFromHost(host: FormattingHost, formatSettings: FormatCodeSettings | undefined): string;
/** @internal */
export declare function lineBreakPart(): SymbolDisplayPart;
/** @internal */
export declare function mapToDisplayParts(writeDisplayParts: (writer: DisplayPartsSymbolWriter) => void): SymbolDisplayPart[];
/** @internal */
export declare function typeToDisplayParts(typechecker: TypeChecker, type: Type, enclosingDeclaration?: Node, flags?: TypeFormatFlags): SymbolDisplayPart[];
/** @internal */
export declare function symbolToDisplayParts(typeChecker: TypeChecker, symbol: Symbol, enclosingDeclaration?: Node, meaning?: SymbolFlags, flags?: SymbolFormatFlags): SymbolDisplayPart[];
/** @internal */
export declare function signatureToDisplayParts(typechecker: TypeChecker, signature: Signature, enclosingDeclaration?: Node, flags?: TypeFormatFlags): SymbolDisplayPart[];
/** @internal */
export declare function nodeToDisplayParts(node: Node, enclosingDeclaration: Node): SymbolDisplayPart[];
/** @internal */
export declare function isImportOrExportSpecifierName(location: Node): location is Identifier;
/** @internal */
export declare function getScriptKind(fileName: string, host: LanguageServiceHost): ScriptKind;
/** @internal */
export declare function getSymbolTarget(symbol: Symbol, checker: TypeChecker): Symbol;
/** @internal */
export declare function getUniqueSymbolId(symbol: Symbol, checker: TypeChecker): number;
/** @internal */
export declare function getFirstNonSpaceCharacterPosition(text: string, position: number): number;
/** @internal */
export declare function getPrecedingNonSpaceCharacterPosition(text: string, position: number): number;
/**
 * Creates a deep, memberwise clone of a node with no source map location.
 *
 * WARNING: This is an expensive operation and is only intended to be used in refactorings
 * and code fixes (because those are triggered by explicit user actions).
 *
 * @internal
 */
export declare function getSynthesizedDeepClone<T extends Node | undefined>(node: T, includeTrivia?: boolean): T;
/** @internal */
export declare function getSynthesizedDeepCloneWithReplacements<T extends Node>(node: T, includeTrivia: boolean, replaceNode: (node: Node) => Node | undefined): T;
/** @internal */
export declare function getSynthesizedDeepClones<T extends Node>(nodes: NodeArray<T>, includeTrivia?: boolean): NodeArray<T>;
/** @internal */
export declare function getSynthesizedDeepClones<T extends Node>(nodes: NodeArray<T> | undefined, includeTrivia?: boolean): NodeArray<T> | undefined;
/** @internal */
export declare function getSynthesizedDeepClonesWithReplacements<T extends Node>(nodes: NodeArray<T>, includeTrivia: boolean, replaceNode: (node: Node) => Node | undefined): NodeArray<T>;
/**
 * Sets EmitFlags to suppress leading and trailing trivia on the node.
 *
 * @internal
 */
export declare function suppressLeadingAndTrailingTrivia(node: Node): void;
/**
 * Sets EmitFlags to suppress leading trivia on the node.
 *
 * @internal
 */
export declare function suppressLeadingTrivia(node: Node): void;
/**
 * Sets EmitFlags to suppress trailing trivia on the node.
 *
 * @internal
 */
export declare function suppressTrailingTrivia(node: Node): void;
/** @internal */
export declare function copyComments(sourceNode: Node, targetNode: Node): void;
/** @internal */
export declare function getUniqueName(baseName: string, sourceFile: SourceFile): string;
/**
 * @return The index of the (only) reference to the extracted symbol.  We want the cursor
 * to be on the reference, rather than the declaration, because it's closer to where the
 * user was before extracting it.
 *
 * @internal
 */
export declare function getRenameLocation(edits: readonly FileTextChanges[], renameFilename: string, name: string, preferLastLocation: boolean): number;
/** @internal */
export declare function copyLeadingComments(sourceNode: Node, targetNode: Node, sourceFile: SourceFile, commentKind?: CommentKind, hasTrailingNewLine?: boolean): void;
/** @internal */
export declare function copyTrailingComments(sourceNode: Node, targetNode: Node, sourceFile: SourceFile, commentKind?: CommentKind, hasTrailingNewLine?: boolean): void;
/**
 * This function copies the trailing comments for the token that comes before `sourceNode`, as leading comments of `targetNode`.
 * This is useful because sometimes a comment that refers to `sourceNode` will be a leading comment for `sourceNode`, according to the
 * notion of trivia ownership, and instead will be a trailing comment for the token before `sourceNode`, e.g.:
 * `function foo(\* not leading comment for a *\ a: string) {}`
 * The comment refers to `a` but belongs to the `(` token, but we might want to copy it.
 *
 * @internal
 */
export declare function copyTrailingAsLeadingComments(sourceNode: Node, targetNode: Node, sourceFile: SourceFile, commentKind?: CommentKind, hasTrailingNewLine?: boolean): void;
/** @internal */
export declare function needsParentheses(expression: Expression): boolean;
/** @internal */
export declare function getContextualTypeFromParent(node: Expression, checker: TypeChecker, contextFlags?: ContextFlags): Type | undefined;
/** @internal */
export declare function quote(sourceFile: SourceFile, preferences: UserPreferences, text: string): string;
/** @internal */
export declare function isEqualityOperatorKind(kind: SyntaxKind): kind is EqualityOperator;
/** @internal */
export declare function isStringLiteralOrTemplate(node: Node): node is StringLiteralLike | TemplateExpression | TaggedTemplateExpression;
/** @internal */
export declare function hasIndexSignature(type: Type): boolean;
/** @internal */
export declare function getSwitchedType(caseClause: CaseClause, checker: TypeChecker): Type | undefined;
/** @internal */
export declare const ANONYMOUS = "anonymous function";
/** @internal */
export declare function getTypeNodeIfAccessible(type: Type, enclosingScope: Node, program: Program, host: LanguageServiceHost): TypeNode | undefined;
/** @internal */
export declare function syntaxRequiresTrailingSemicolonOrASI(kind: SyntaxKind): boolean;
/** @internal */
export declare const syntaxMayBeASICandidate: (kind: SyntaxKind) => boolean;
/** @internal */
export declare function positionIsASICandidate(pos: number, context: Node, sourceFile: SourceFileLike): boolean;
/** @internal */
export declare function probablyUsesSemicolons(sourceFile: SourceFile): boolean;
/** @internal */
export declare function tryGetDirectories(host: Pick<LanguageServiceHost, "getDirectories">, directoryName: string): string[];
/** @internal */
export declare function tryReadDirectory(host: Pick<LanguageServiceHost, "readDirectory">, path: string, extensions?: readonly string[], exclude?: readonly string[], include?: readonly string[]): readonly string[];
/** @internal */
export declare function tryFileExists(host: Pick<LanguageServiceHost, "fileExists">, path: string): boolean;
/** @internal */
export declare function tryDirectoryExists(host: LanguageServiceHost, path: string): boolean;
/** @internal */
export declare function tryAndIgnoreErrors<T>(cb: () => T): T | undefined;
/** @internal */
export declare function tryIOAndConsumeErrors<T>(host: unknown, toApply: ((...a: any[]) => T) | undefined, ...args: any[]): any;
/** @internal */
export declare function findPackageJsons(startDirectory: string, host: Pick<LanguageServiceHost, "fileExists">, stopDirectory?: string): string[];
/** @internal */
export declare function findPackageJson(directory: string, host: LanguageServiceHost): string | undefined;
/** @internal */
export declare function getPackageJsonsVisibleToFile(fileName: string, host: LanguageServiceHost): readonly ProjectPackageJsonInfo[];
/** @internal */
export declare function createPackageJsonInfo(fileName: string, host: {
    readFile?(fileName: string): string | undefined;
}): ProjectPackageJsonInfo | undefined;
/** @internal */
export interface PackageJsonImportFilter {
    allowsImportingAmbientModule: (moduleSymbol: Symbol, moduleSpecifierResolutionHost: ModuleSpecifierResolutionHost) => boolean;
    allowsImportingSourceFile: (sourceFile: SourceFile, moduleSpecifierResolutionHost: ModuleSpecifierResolutionHost) => boolean;
    /**
     * Use for a specific module specifier that has already been resolved.
     * Use `allowsImportingAmbientModule` or `allowsImportingSourceFile` to resolve
     * the best module specifier for a given module _and_ determine if it's importable.
     */
    allowsImportingSpecifier: (moduleSpecifier: string) => boolean;
}
/** @internal */
export declare function createPackageJsonImportFilter(fromFile: SourceFile, preferences: UserPreferences, host: LanguageServiceHost): PackageJsonImportFilter;
/** @internal */
export declare function consumesNodeCoreModules(sourceFile: SourceFile): boolean;
/** @internal */
export declare function isInsideNodeModules(fileOrDirectory: string): boolean;
/** @internal */
export declare function isDiagnosticWithLocation(diagnostic: Diagnostic): diagnostic is DiagnosticWithLocation;
/** @internal */
export declare function findDiagnosticForNode(node: Node, sortedFileDiagnostics: readonly Diagnostic[]): DiagnosticWithLocation | undefined;
/** @internal */
export declare function getDiagnosticsWithinSpan(span: TextSpan, sortedFileDiagnostics: readonly Diagnostic[]): readonly DiagnosticWithLocation[];
/** @internal */
export declare function getRefactorContextSpan({ startPosition, endPosition }: RefactorContext): TextSpan;
/** @internal */
export declare function getFixableErrorSpanExpression(sourceFile: SourceFile, span: TextSpan): Expression | undefined;
/**
 * If the provided value is an array, the mapping function is applied to each element; otherwise, the mapping function is applied
 * to the provided value itself.
 *
 * @internal
 */
export declare function mapOneOrMany<T, U>(valueOrArray: T | readonly T[], f: (x: T, i: number) => U): U | U[];
/** @internal */
export declare function mapOneOrMany<T, U>(valueOrArray: T | readonly T[] | undefined, f: (x: T, i: number) => U): U | U[] | undefined;
/** @internal */
export declare function mapOneOrMany<T, U>(valueOrArray: T | readonly T[], f: (x: T, i: number) => U, resultSelector: (x: U[]) => U): U;
/** @internal */
export declare function mapOneOrMany<T, U>(valueOrArray: T | readonly T[] | undefined, f: (x: T, i: number) => U, resultSelector: (x: U[]) => U): U | undefined;
/**
 * If the provided value is an array, the first element of the array is returned; otherwise, the provided value is returned instead.
 *
 * @internal
 */
export declare function firstOrOnly<T>(valueOrArray: T | readonly T[]): T;
/** @internal */
export declare function getNamesForExportedSymbol(symbol: Symbol, scriptTarget: ScriptTarget | undefined): string | [lowercase: string, capitalized: string];
/** @internal */
export declare function getNameForExportedSymbol(symbol: Symbol, scriptTarget: ScriptTarget | undefined, preferCapitalized?: boolean): string;
/**
 * Useful to check whether a string contains another string at a specific index
 * without allocating another string or traversing the entire contents of the outer string.
 *
 * This function is useful in place of either of the following:
 *
 * ```ts
 * // Allocates
 * haystack.substr(startIndex, needle.length) === needle
 *
 * // Full traversal
 * haystack.indexOf(needle, startIndex) === startIndex
 * ```
 *
 * @param haystack The string that potentially contains `needle`.
 * @param needle The string whose content might sit within `haystack`.
 * @param startIndex The index within `haystack` to start searching for `needle`.
 *
 * @internal
 */
export declare function stringContainsAt(haystack: string, needle: string, startIndex: number): boolean;
/** @internal */
export declare function startsWithUnderscore(name: string): boolean;
/** @internal */
export declare function isGlobalDeclaration(declaration: Declaration): boolean;
/** @internal */
export declare function isNonGlobalDeclaration(declaration: Declaration): boolean;
/** @internal */
export declare function isDeprecatedDeclaration(decl: Declaration): boolean;
/** @internal */
export declare function shouldUseUriStyleNodeCoreModules(file: SourceFile, program: Program): boolean;
/** @internal */
export declare function getNewLineKind(newLineCharacter: string): NewLineKind;
/** @internal */
export type DiagnosticOrDiagnosticAndArguments = DiagnosticMessage | DiagnosticAndArguments;
/** @internal */
export declare function diagnosticToString(diag: DiagnosticOrDiagnosticAndArguments): string;
/**
 * Get format code settings for a code writing context (e.g. when formatting text changes or completions code).
 *
 * @internal
 */
export declare function getFormatCodeSettingsForWriting({ options }: formatting.FormatContext, sourceFile: SourceFile): FormatCodeSettings;
/** @internal */
export declare function jsxModeNeedsExplicitImport(jsx: JsxEmit | undefined): boolean;
/** @internal */
export declare function isSourceFileFromLibrary(program: Program, node: SourceFile): boolean;
/** @internal */
export interface CaseClauseTracker {
    addValue(value: string | number): void;
    hasValue(value: string | number | PseudoBigInt): boolean;
}
/** @internal */
export declare function newCaseClauseTracker(checker: TypeChecker, clauses: readonly (CaseClause | DefaultClause)[]): CaseClauseTracker;
/** @internal */
export declare function fileShouldUseJavaScriptRequire(file: SourceFile | string, program: Program, host: LanguageServiceHost, preferRequire?: boolean): boolean | undefined;
//# sourceMappingURL=utilities.d.ts.map