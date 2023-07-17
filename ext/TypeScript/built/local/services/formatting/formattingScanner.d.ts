import { LanguageVariant, Node, NodeArray } from "../_namespaces/ts";
import { TextRangeWithKind, TokenInfo } from "../_namespaces/ts.formatting";
/** @internal */
export interface FormattingScanner {
    advance(): void;
    getTokenFullStart(): number;
    /** @deprecated use {@link getTokenFullStart} */
    getStartPos(): number;
    isOnToken(): boolean;
    isOnEOF(): boolean;
    readTokenInfo(n: Node): TokenInfo;
    readEOFTokenRange(): TextRangeWithKind;
    getCurrentLeadingTrivia(): TextRangeWithKind[] | undefined;
    lastTrailingTriviaWasNewLine(): boolean;
    skipToEndOf(node: Node | NodeArray<Node>): void;
    skipToStartOf(node: Node): void;
}
/** @internal */
export declare function getFormattingScanner<T>(text: string, languageVariant: LanguageVariant, startPos: number, endPos: number, cb: (scanner: FormattingScanner) => T): T;
//# sourceMappingURL=formattingScanner.d.ts.map