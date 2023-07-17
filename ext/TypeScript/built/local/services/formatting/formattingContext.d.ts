import { FormatCodeSettings, Node, SourceFileLike } from "../_namespaces/ts";
import { TextRangeWithKind } from "../_namespaces/ts.formatting";
/** @internal */
export declare const enum FormattingRequestKind {
    FormatDocument = 0,
    FormatSelection = 1,
    FormatOnEnter = 2,
    FormatOnSemicolon = 3,
    FormatOnOpeningCurlyBrace = 4,
    FormatOnClosingCurlyBrace = 5
}
/** @internal */
export declare class FormattingContext {
    readonly sourceFile: SourceFileLike;
    formattingRequestKind: FormattingRequestKind;
    options: FormatCodeSettings;
    currentTokenSpan: TextRangeWithKind;
    nextTokenSpan: TextRangeWithKind;
    contextNode: Node;
    currentTokenParent: Node;
    nextTokenParent: Node;
    private contextNodeAllOnSameLine;
    private nextNodeAllOnSameLine;
    private tokensAreOnSameLine;
    private contextNodeBlockIsOnOneLine;
    private nextNodeBlockIsOnOneLine;
    constructor(sourceFile: SourceFileLike, formattingRequestKind: FormattingRequestKind, options: FormatCodeSettings);
    updateContext(currentRange: TextRangeWithKind, currentTokenParent: Node, nextRange: TextRangeWithKind, nextTokenParent: Node, commonParent: Node): void;
    ContextNodeAllOnSameLine(): boolean;
    NextNodeAllOnSameLine(): boolean;
    TokensAreOnSameLine(): boolean;
    ContextNodeBlockIsOnOneLine(): boolean;
    NextNodeBlockIsOnOneLine(): boolean;
    private NodeIsOnOneLine;
    private BlockIsOnOneLine;
}
//# sourceMappingURL=formattingContext.d.ts.map