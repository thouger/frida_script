import { CommentRange, EditorSettings, FormatCodeSettings, FormattingHost, LanguageVariant, Node, SourceFile, SourceFileLike, SyntaxKind, TextChange, TextRange, TriviaSyntaxKind } from "../_namespaces/ts";
import { RulesMap } from "../_namespaces/ts.formatting";
/** @internal */
export interface FormatContext {
    readonly options: FormatCodeSettings;
    readonly getRules: RulesMap;
    readonly host: FormattingHost;
}
/** @internal */
export interface TextRangeWithKind<T extends SyntaxKind = SyntaxKind> extends TextRange {
    kind: T;
}
/** @internal */
export type TextRangeWithTriviaKind = TextRangeWithKind<TriviaSyntaxKind>;
/** @internal */
export interface TokenInfo {
    leadingTrivia: TextRangeWithTriviaKind[] | undefined;
    token: TextRangeWithKind;
    trailingTrivia: TextRangeWithTriviaKind[] | undefined;
}
/** @internal */
export declare function createTextRangeWithKind<T extends SyntaxKind>(pos: number, end: number, kind: T): TextRangeWithKind<T>;
/** @internal */
export declare function formatOnEnter(position: number, sourceFile: SourceFile, formatContext: FormatContext): TextChange[];
/** @internal */
export declare function formatOnSemicolon(position: number, sourceFile: SourceFile, formatContext: FormatContext): TextChange[];
/** @internal */
export declare function formatOnOpeningCurly(position: number, sourceFile: SourceFile, formatContext: FormatContext): TextChange[];
/** @internal */
export declare function formatOnClosingCurly(position: number, sourceFile: SourceFile, formatContext: FormatContext): TextChange[];
/** @internal */
export declare function formatDocument(sourceFile: SourceFile, formatContext: FormatContext): TextChange[];
/** @internal */
export declare function formatSelection(start: number, end: number, sourceFile: SourceFile, formatContext: FormatContext): TextChange[];
/** @internal */
export declare function formatNodeGivenIndentation(node: Node, sourceFileLike: SourceFileLike, languageVariant: LanguageVariant, initialIndentation: number, delta: number, formatContext: FormatContext): TextChange[];
/**
 *
 * @internal
 */
export declare function getRangeOfEnclosingComment(sourceFile: SourceFile, position: number, precedingToken?: Node | null, tokenAtPosition?: Node): CommentRange | undefined;
/** @internal */
export declare function getIndentationString(indentation: number, options: EditorSettings): string;
//# sourceMappingURL=formatting.d.ts.map