import { EditorSettings, FormatCodeSettings, Node, NodeArray, SourceFile, SourceFileLike, TextRange } from "../_namespaces/ts";
import { TextRangeWithKind } from "../_namespaces/ts.formatting";
/** @internal */
export declare namespace SmartIndenter {
    /**
     * @param assumeNewLineBeforeCloseBrace
     * `false` when called on text from a real source file.
     * `true` when we need to assume `position` is on a newline.
     *
     * This is useful for codefixes. Consider
     * ```
     * function f() {
     * |}
     * ```
     * with `position` at `|`.
     *
     * When inserting some text after an open brace, we would like to get indentation as if a newline was already there.
     * By default indentation at `position` will be 0 so 'assumeNewLineBeforeCloseBrace' overrides this behavior.
     */
    function getIndentation(position: number, sourceFile: SourceFile, options: EditorSettings, assumeNewLineBeforeCloseBrace?: boolean): number;
    function getIndentationForNode(n: Node, ignoreActualIndentationRange: TextRange, sourceFile: SourceFile, options: EditorSettings): number;
    function getBaseIndentation(options: EditorSettings): number;
    function isArgumentAndStartLineOverlapsExpressionBeingCalled(parent: Node, child: Node, childStartLine: number, sourceFile: SourceFileLike): boolean;
    function childStartsOnTheSameLineWithElseInIfStatement(parent: Node, child: TextRangeWithKind, childStartLine: number, sourceFile: SourceFileLike): boolean;
    function childIsUnindentedBranchOfConditionalExpression(parent: Node, child: TextRangeWithKind, childStartLine: number, sourceFile: SourceFileLike): boolean;
    function argumentStartsOnSameLineAsPreviousArgument(parent: Node, child: TextRangeWithKind, childStartLine: number, sourceFile: SourceFileLike): boolean;
    function getContainingList(node: Node, sourceFile: SourceFile): NodeArray<Node> | undefined;
    /**
     * Character is the actual index of the character since the beginning of the line.
     * Column - position of the character after expanding tabs to spaces.
     * "0\t2$"
     * value of 'character' for '$' is 3
     * value of 'column' for '$' is 6 (assuming that tab size is 4)
     */
    function findFirstNonWhitespaceCharacterAndColumn(startPos: number, endPos: number, sourceFile: SourceFileLike, options: EditorSettings): {
        column: number;
        character: number;
    };
    function findFirstNonWhitespaceColumn(startPos: number, endPos: number, sourceFile: SourceFileLike, options: EditorSettings): number;
    function nodeWillIndentChild(settings: FormatCodeSettings, parent: TextRangeWithKind, child: TextRangeWithKind | undefined, sourceFile: SourceFileLike | undefined, indentByDefault: boolean): boolean;
    /**
     * True when the parent node should indent the given child by an explicit rule.
     * @param isNextChild If true, we are judging indent of a hypothetical child *after* this one, not the current child.
     */
    function shouldIndentChildNode(settings: FormatCodeSettings, parent: TextRangeWithKind, child?: Node, sourceFile?: SourceFileLike, isNextChild?: boolean): boolean;
}
//# sourceMappingURL=smartIndenter.d.ts.map