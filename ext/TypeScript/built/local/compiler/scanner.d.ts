import { CommentDirective, CommentKind, CommentRange, DiagnosticMessage, JSDocSyntaxKind, JsxTokenSyntaxKind, KeywordSyntaxKind, LanguageVariant, LineAndCharacter, MapLike, PunctuationOrKeywordSyntaxKind, ScriptTarget, SourceFileLike, SyntaxKind, TokenFlags } from "./_namespaces/ts";
export type ErrorCallback = (message: DiagnosticMessage, length: number, arg0?: any) => void;
/** @internal */
export declare function tokenIsIdentifierOrKeyword(token: SyntaxKind): boolean;
/** @internal */
export declare function tokenIsIdentifierOrKeywordOrGreaterThan(token: SyntaxKind): boolean;
export interface Scanner {
    /** @deprecated use {@link getTokenFullStart} */
    getStartPos(): number;
    getToken(): SyntaxKind;
    getTokenFullStart(): number;
    getTokenStart(): number;
    getTokenEnd(): number;
    /** @deprecated use {@link getTokenEnd} */
    getTextPos(): number;
    /** @deprecated use {@link getTokenStart} */
    getTokenPos(): number;
    getTokenText(): string;
    getTokenValue(): string;
    hasUnicodeEscape(): boolean;
    hasExtendedUnicodeEscape(): boolean;
    hasPrecedingLineBreak(): boolean;
    /** @internal */
    hasPrecedingJSDocComment(): boolean;
    isIdentifier(): boolean;
    isReservedWord(): boolean;
    isUnterminated(): boolean;
    /** @internal */
    getNumericLiteralFlags(): TokenFlags;
    /** @internal */
    getCommentDirectives(): CommentDirective[] | undefined;
    /** @internal */
    getTokenFlags(): TokenFlags;
    reScanGreaterToken(): SyntaxKind;
    reScanSlashToken(): SyntaxKind;
    reScanAsteriskEqualsToken(): SyntaxKind;
    reScanTemplateToken(isTaggedTemplate: boolean): SyntaxKind;
    /** @deprecated use {@link reScanTemplateToken}(false) */
    reScanTemplateHeadOrNoSubstitutionTemplate(): SyntaxKind;
    scanJsxIdentifier(): SyntaxKind;
    scanJsxAttributeValue(): SyntaxKind;
    reScanJsxAttributeValue(): SyntaxKind;
    reScanJsxToken(allowMultilineJsxText?: boolean): JsxTokenSyntaxKind;
    reScanLessThanToken(): SyntaxKind;
    reScanHashToken(): SyntaxKind;
    reScanQuestionToken(): SyntaxKind;
    reScanInvalidIdentifier(): SyntaxKind;
    scanJsxToken(): JsxTokenSyntaxKind;
    scanJsDocToken(): JSDocSyntaxKind;
    /** @internal */
    scanJSDocCommentTextToken(inBackticks: boolean): JSDocSyntaxKind | SyntaxKind.JSDocCommentTextToken;
    scan(): SyntaxKind;
    getText(): string;
    /** @internal */
    clearCommentDirectives(): void;
    setText(text: string | undefined, start?: number, length?: number): void;
    setOnError(onError: ErrorCallback | undefined): void;
    setScriptTarget(scriptTarget: ScriptTarget): void;
    setLanguageVariant(variant: LanguageVariant): void;
    /** @deprecated use {@link resetTokenState} */
    setTextPos(textPos: number): void;
    resetTokenState(pos: number): void;
    /** @internal */
    setInJSDocType(inType: boolean): void;
    lookAhead<T>(callback: () => T): T;
    scanRange<T>(start: number, length: number, callback: () => T): T;
    tryScan<T>(callback: () => T): T;
}
/** @internal */
export declare const textToKeywordObj: MapLike<KeywordSyntaxKind>;
/** @internal */ export declare function isUnicodeIdentifierStart(code: number, languageVersion: ScriptTarget | undefined): boolean;
/** @internal */
export declare function tokenToString(t: PunctuationOrKeywordSyntaxKind): string;
export declare function tokenToString(t: SyntaxKind): string | undefined;
/** @internal */
export declare function stringToToken(s: string): SyntaxKind | undefined;
/** @internal */
export declare function computeLineStarts(text: string): number[];
export declare function getPositionOfLineAndCharacter(sourceFile: SourceFileLike, line: number, character: number): number;
/** @internal */
export declare function getPositionOfLineAndCharacter(sourceFile: SourceFileLike, line: number, character: number, allowEdits?: true): number;
/** @internal */
export declare function computePositionOfLineAndCharacter(lineStarts: readonly number[], line: number, character: number, debugText?: string, allowEdits?: true): number;
/** @internal */
export declare function getLineStarts(sourceFile: SourceFileLike): readonly number[];
/** @internal */
export declare function computeLineAndCharacterOfPosition(lineStarts: readonly number[], position: number): LineAndCharacter;
/**
 * @internal
 * We assume the first line starts at position 0 and 'position' is non-negative.
 */
export declare function computeLineOfPosition(lineStarts: readonly number[], position: number, lowerBound?: number): number;
/** @internal */
export declare function getLinesBetweenPositions(sourceFile: SourceFileLike, pos1: number, pos2: number): number;
export declare function getLineAndCharacterOfPosition(sourceFile: SourceFileLike, position: number): LineAndCharacter;
export declare function isWhiteSpaceLike(ch: number): boolean;
/** Does not include line breaks. For that, see isWhiteSpaceLike. */
export declare function isWhiteSpaceSingleLine(ch: number): boolean;
export declare function isLineBreak(ch: number): boolean;
/** @internal */
export declare function isOctalDigit(ch: number): boolean;
export declare function couldStartTrivia(text: string, pos: number): boolean;
/** @internal */
export declare function skipTrivia(text: string, pos: number, stopAfterLineBreak?: boolean, stopAtComments?: boolean, inJSDoc?: boolean): number;
/** @internal */
export declare function isShebangTrivia(text: string, pos: number): boolean;
/** @internal */
export declare function scanShebangTrivia(text: string, pos: number): number;
export declare function forEachLeadingCommentRange<U>(text: string, pos: number, cb: (pos: number, end: number, kind: CommentKind, hasTrailingNewLine: boolean) => U): U | undefined;
export declare function forEachLeadingCommentRange<T, U>(text: string, pos: number, cb: (pos: number, end: number, kind: CommentKind, hasTrailingNewLine: boolean, state: T) => U, state: T): U | undefined;
export declare function forEachTrailingCommentRange<U>(text: string, pos: number, cb: (pos: number, end: number, kind: CommentKind, hasTrailingNewLine: boolean) => U): U | undefined;
export declare function forEachTrailingCommentRange<T, U>(text: string, pos: number, cb: (pos: number, end: number, kind: CommentKind, hasTrailingNewLine: boolean, state: T) => U, state: T): U | undefined;
export declare function reduceEachLeadingCommentRange<T, U>(text: string, pos: number, cb: (pos: number, end: number, kind: CommentKind, hasTrailingNewLine: boolean, state: T) => U, state: T, initial: U): U | undefined;
export declare function reduceEachTrailingCommentRange<T, U>(text: string, pos: number, cb: (pos: number, end: number, kind: CommentKind, hasTrailingNewLine: boolean, state: T) => U, state: T, initial: U): U | undefined;
export declare function getLeadingCommentRanges(text: string, pos: number): CommentRange[] | undefined;
export declare function getTrailingCommentRanges(text: string, pos: number): CommentRange[] | undefined;
/** Optionally, get the shebang */
export declare function getShebang(text: string): string | undefined;
export declare function isIdentifierStart(ch: number, languageVersion: ScriptTarget | undefined): boolean;
export declare function isIdentifierPart(ch: number, languageVersion: ScriptTarget | undefined, identifierVariant?: LanguageVariant): boolean;
/** @internal */
export declare function isIdentifierText(name: string, languageVersion: ScriptTarget | undefined, identifierVariant?: LanguageVariant): boolean;
export declare function createScanner(languageVersion: ScriptTarget, skipTrivia: boolean, languageVariant?: LanguageVariant, textInitial?: string, onError?: ErrorCallback, start?: number, length?: number): Scanner;
/** @internal */
export declare function utf16EncodeAsString(codePoint: number): string;
//# sourceMappingURL=scanner.d.ts.map