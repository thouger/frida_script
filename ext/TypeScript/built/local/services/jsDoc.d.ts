import { CompletionEntry, CompletionEntryDetails, Declaration, DocCommentTemplateOptions, JSDocParameterTag, JSDocTagInfo, SourceFile, SymbolDisplayPart, TextInsertion, TypeChecker } from "./_namespaces/ts";
/** @internal */
export declare function getJsDocCommentsFromDeclarations(declarations: readonly Declaration[], checker?: TypeChecker): SymbolDisplayPart[];
/** @internal */
export declare function getJsDocTagsFromDeclarations(declarations?: Declaration[], checker?: TypeChecker): JSDocTagInfo[];
/** @internal */
export declare function getJSDocTagNameCompletions(): CompletionEntry[];
/** @internal */
export declare const getJSDocTagNameCompletionDetails: typeof getJSDocTagCompletionDetails;
/** @internal */
export declare function getJSDocTagCompletions(): CompletionEntry[];
/** @internal */
export declare function getJSDocTagCompletionDetails(name: string): CompletionEntryDetails;
/** @internal */
export declare function getJSDocParameterNameCompletions(tag: JSDocParameterTag): CompletionEntry[];
/** @internal */
export declare function getJSDocParameterNameCompletionDetails(name: string): CompletionEntryDetails;
/**
 * Checks if position points to a valid position to add JSDoc comments, and if so,
 * returns the appropriate template. Otherwise returns an empty string.
 * Valid positions are
 *      - outside of comments, statements, and expressions, and
 *      - preceding a:
 *          - function/constructor/method declaration
 *          - class declarations
 *          - variable statements
 *          - namespace declarations
 *          - interface declarations
 *          - method signatures
 *          - type alias declarations
 *
 * Hosts should ideally check that:
 * - The line is all whitespace up to 'position' before performing the insertion.
 * - If the keystroke sequence "/\*\*" induced the call, we also check that the next
 * non-whitespace character is '*', which (approximately) indicates whether we added
 * the second '*' to complete an existing (JSDoc) comment.
 * @param fileName The file in which to perform the check.
 * @param position The (character-indexed) position in the file where the check should
 * be performed.
 *
 * @internal
 */
export declare function getDocCommentTemplateAtPosition(newLine: string, sourceFile: SourceFile, position: number, options?: DocCommentTemplateOptions): TextInsertion | undefined;
//# sourceMappingURL=jsDoc.d.ts.map