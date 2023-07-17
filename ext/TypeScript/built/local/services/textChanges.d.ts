import { ArrowFunction, ClassElement, ClassExpression, ClassLikeDeclaration, ConstructorDeclaration, DeclarationStatement, EmitTextWriter, Expression, FileTextChanges, formatting, FunctionDeclaration, FunctionExpression, HasJSDoc, ImportSpecifier, InterfaceDeclaration, JSDoc, JSDocTag, LanguageServiceHost, MethodSignature, Modifier, NamedImports, Node, NodeArray, ObjectLiteralElementLike, ObjectLiteralExpression, ParameterDeclaration, PrintHandlers, PropertyAssignment, PropertyDeclaration, PropertySignature, SignatureDeclaration, SourceFile, Statement, SyntaxKind, TextChange, TextRange, TypeLiteralNode, TypeNode, TypeParameterDeclaration, UserPreferences, VariableDeclaration, VariableStatement } from "./_namespaces/ts";
/** @internal */
export interface ConfigurableStart {
    leadingTriviaOption?: LeadingTriviaOption;
}
/** @internal */
export interface ConfigurableEnd {
    trailingTriviaOption?: TrailingTriviaOption;
}
/** @internal */
export declare enum LeadingTriviaOption {
    /** Exclude all leading trivia (use getStart()) */
    Exclude = 0,
    /** Include leading trivia and,
     * if there are no line breaks between the node and the previous token,
     * include all trivia between the node and the previous token
     */
    IncludeAll = 1,
    /**
     * Include attached JSDoc comments
     */
    JSDoc = 2,
    /**
     * Only delete trivia on the same line as getStart().
     * Used to avoid deleting leading comments
     */
    StartLine = 3
}
/** @internal */
export declare enum TrailingTriviaOption {
    /** Exclude all trailing trivia (use getEnd()) */
    Exclude = 0,
    /** Doesn't include whitespace, but does strip comments */
    ExcludeWhitespace = 1,
    /** Include trailing trivia */
    Include = 2
}
/**
 * Usually node.pos points to a position immediately after the previous token.
 * If this position is used as a beginning of the span to remove - it might lead to removing the trailing trivia of the previous node, i.e:
 * const x; // this is x
 *        ^ - pos for the next variable declaration will point here
 * const y; // this is y
 *        ^ - end for previous variable declaration
 * Usually leading trivia of the variable declaration 'y' should not include trailing trivia (whitespace, comment 'this is x' and newline) from the preceding
 * variable declaration and trailing trivia for 'y' should include (whitespace, comment 'this is y', newline).
 * By default when removing nodes we adjust start and end positions to respect specification of the trivia above.
 * If pos\end should be interpreted literally (that is, withouth including leading and trailing trivia), `leadingTriviaOption` should be set to `LeadingTriviaOption.Exclude`
 * and `trailingTriviaOption` to `TrailingTriviaOption.Exclude`.
 *
 * @internal
 */
export interface ConfigurableStartEnd extends ConfigurableStart, ConfigurableEnd {
}
/** @internal */
export interface InsertNodeOptions {
    /**
     * Text to be inserted before the new node
     */
    prefix?: string;
    /**
     * Text to be inserted after the new node
     */
    suffix?: string;
    /**
     * Text of inserted node will be formatted with this indentation, otherwise indentation will be inferred from the old node
     */
    indentation?: number;
    /**
     * Text of inserted node will be formatted with this delta, otherwise delta will be inferred from the new node kind
     */
    delta?: number;
}
/** @internal */
export interface ReplaceWithMultipleNodesOptions extends InsertNodeOptions {
    readonly joiner?: string;
}
/** @internal */
export interface ChangeNodeOptions extends ConfigurableStartEnd, InsertNodeOptions {
}
/** @internal */
export interface TextChangesContext {
    host: LanguageServiceHost;
    formatContext: formatting.FormatContext;
    preferences: UserPreferences;
}
/** @internal */
export type TypeAnnotatable = SignatureDeclaration | VariableDeclaration | ParameterDeclaration | PropertyDeclaration | PropertySignature;
/** @internal */
export type ThisTypeAnnotatable = FunctionDeclaration | FunctionExpression;
/** @internal */
export declare function isThisTypeAnnotatable(containingFunction: SignatureDeclaration): containingFunction is ThisTypeAnnotatable;
/** @internal */
export declare class ChangeTracker {
    private readonly newLineCharacter;
    private readonly formatContext;
    private readonly changes;
    private newFileChanges?;
    private readonly classesWithNodesInsertedAtStart;
    private readonly deletedNodes;
    static fromContext(context: TextChangesContext): ChangeTracker;
    static with(context: TextChangesContext, cb: (tracker: ChangeTracker) => void): FileTextChanges[];
    /** Public for tests only. Other callers should use `ChangeTracker.with`. */
    constructor(newLineCharacter: string, formatContext: formatting.FormatContext);
    pushRaw(sourceFile: SourceFile, change: FileTextChanges): void;
    deleteRange(sourceFile: SourceFile, range: TextRange): void;
    delete(sourceFile: SourceFile, node: Node | NodeArray<TypeParameterDeclaration>): void;
    /** Stop! Consider using `delete` instead, which has logic for deleting nodes from delimited lists. */
    deleteNode(sourceFile: SourceFile, node: Node, options?: ConfigurableStartEnd): void;
    deleteNodes(sourceFile: SourceFile, nodes: readonly Node[], options: ConfigurableStartEnd | undefined, hasTrailingComment: boolean): void;
    deleteModifier(sourceFile: SourceFile, modifier: Modifier): void;
    deleteNodeRange(sourceFile: SourceFile, startNode: Node, endNode: Node, options?: ConfigurableStartEnd): void;
    deleteNodeRangeExcludingEnd(sourceFile: SourceFile, startNode: Node, afterEndNode: Node | undefined, options?: ConfigurableStartEnd): void;
    replaceRange(sourceFile: SourceFile, range: TextRange, newNode: Node, options?: InsertNodeOptions): void;
    replaceNode(sourceFile: SourceFile, oldNode: Node, newNode: Node, options?: ChangeNodeOptions): void;
    replaceNodeRange(sourceFile: SourceFile, startNode: Node, endNode: Node, newNode: Node, options?: ChangeNodeOptions): void;
    private replaceRangeWithNodes;
    replaceNodeWithNodes(sourceFile: SourceFile, oldNode: Node, newNodes: readonly Node[], options?: ChangeNodeOptions): void;
    replaceNodeWithText(sourceFile: SourceFile, oldNode: Node, text: string): void;
    replaceNodeRangeWithNodes(sourceFile: SourceFile, startNode: Node, endNode: Node, newNodes: readonly Node[], options?: ReplaceWithMultipleNodesOptions & ConfigurableStartEnd): void;
    nodeHasTrailingComment(sourceFile: SourceFile, oldNode: Node, configurableEnd?: ConfigurableEnd): boolean;
    private nextCommaToken;
    replacePropertyAssignment(sourceFile: SourceFile, oldNode: PropertyAssignment, newNode: PropertyAssignment): void;
    insertNodeAt(sourceFile: SourceFile, pos: number, newNode: Node, options?: InsertNodeOptions): void;
    private insertNodesAt;
    insertNodeAtTopOfFile(sourceFile: SourceFile, newNode: Statement, blankLineBetween: boolean): void;
    insertNodesAtTopOfFile(sourceFile: SourceFile, newNodes: readonly Statement[], blankLineBetween: boolean): void;
    private insertAtTopOfFile;
    insertNodesAtEndOfFile(sourceFile: SourceFile, newNodes: readonly Statement[], blankLineBetween: boolean): void;
    private insertAtEndOfFile;
    private insertStatementsInNewFile;
    insertFirstParameter(sourceFile: SourceFile, parameters: NodeArray<ParameterDeclaration>, newParam: ParameterDeclaration): void;
    insertNodeBefore(sourceFile: SourceFile, before: Node, newNode: Node, blankLineBetween?: boolean, options?: ConfigurableStartEnd): void;
    insertModifierAt(sourceFile: SourceFile, pos: number, modifier: SyntaxKind, options?: InsertNodeOptions): void;
    insertModifierBefore(sourceFile: SourceFile, modifier: SyntaxKind, before: Node): void;
    insertCommentBeforeLine(sourceFile: SourceFile, lineNumber: number, position: number, commentText: string): void;
    insertJsdocCommentBefore(sourceFile: SourceFile, node: HasJSDoc, tag: JSDoc): void;
    private createJSDocText;
    replaceJSDocComment(sourceFile: SourceFile, node: HasJSDoc, tags: readonly JSDocTag[]): void;
    addJSDocTags(sourceFile: SourceFile, parent: HasJSDoc, newTags: readonly JSDocTag[]): void;
    filterJSDocTags(sourceFile: SourceFile, parent: HasJSDoc, predicate: (tag: JSDocTag) => boolean): void;
    replaceRangeWithText(sourceFile: SourceFile, range: TextRange, text: string): void;
    insertText(sourceFile: SourceFile, pos: number, text: string): void;
    /** Prefer this over replacing a node with another that has a type annotation, as it avoids reformatting the other parts of the node. */
    tryInsertTypeAnnotation(sourceFile: SourceFile, node: TypeAnnotatable, type: TypeNode): boolean;
    tryInsertThisTypeAnnotation(sourceFile: SourceFile, node: ThisTypeAnnotatable, type: TypeNode): void;
    insertTypeParameters(sourceFile: SourceFile, node: SignatureDeclaration, typeParameters: readonly TypeParameterDeclaration[]): void;
    private getOptionsForInsertNodeBefore;
    insertNodeAtConstructorStart(sourceFile: SourceFile, ctr: ConstructorDeclaration, newStatement: Statement): void;
    insertNodeAtConstructorStartAfterSuperCall(sourceFile: SourceFile, ctr: ConstructorDeclaration, newStatement: Statement): void;
    insertNodeAtConstructorEnd(sourceFile: SourceFile, ctr: ConstructorDeclaration, newStatement: Statement): void;
    private replaceConstructorBody;
    insertNodeAtEndOfScope(sourceFile: SourceFile, scope: Node, newNode: Node): void;
    insertMemberAtStart(sourceFile: SourceFile, node: ClassLikeDeclaration | InterfaceDeclaration | TypeLiteralNode, newElement: ClassElement | PropertySignature | MethodSignature): void;
    insertNodeAtObjectStart(sourceFile: SourceFile, obj: ObjectLiteralExpression, newElement: ObjectLiteralElementLike): void;
    private insertNodeAtStartWorker;
    /**
     * Tries to guess the indentation from the existing members of a class/interface/object. All members must be on
     * new lines and must share the same indentation.
     */
    private guessIndentationFromExistingMembers;
    private computeIndentationForNewMember;
    private getInsertNodeAtStartInsertOptions;
    insertNodeAfterComma(sourceFile: SourceFile, after: Node, newNode: Node): void;
    insertNodeAfter(sourceFile: SourceFile, after: Node, newNode: Node): void;
    insertNodeAtEndOfList(sourceFile: SourceFile, list: NodeArray<Node>, newNode: Node): void;
    insertNodesAfter(sourceFile: SourceFile, after: Node, newNodes: readonly Node[]): void;
    private insertNodeAfterWorker;
    private getInsertNodeAfterOptions;
    private getInsertNodeAfterOptionsWorker;
    insertName(sourceFile: SourceFile, node: FunctionExpression | ClassExpression | ArrowFunction, name: string): void;
    insertExportModifier(sourceFile: SourceFile, node: DeclarationStatement | VariableStatement): void;
    insertImportSpecifierAtIndex(sourceFile: SourceFile, importSpecifier: ImportSpecifier, namedImports: NamedImports, index: number): void;
    /**
     * This function should be used to insert nodes in lists when nodes don't carry separators as the part of the node range,
     * i.e. arguments in arguments lists, parameters in parameter lists etc.
     * Note that separators are part of the node in statements and class elements.
     */
    insertNodeInListAfter(sourceFile: SourceFile, after: Node, newNode: Node, containingList?: NodeArray<Node> | undefined): void;
    parenthesizeExpression(sourceFile: SourceFile, expression: Expression): void;
    private finishClassesWithNodesInsertedAtStart;
    private finishDeleteDeclarations;
    /**
     * Note: after calling this, the TextChanges object must be discarded!
     * @param validate only for tests
     *    The reason we must validate as part of this method is that `getNonFormattedText` changes the node's positions,
     *    so we can only call this once and can't get the non-formatted text separately.
     */
    getChanges(validate?: ValidateNonFormattedText): FileTextChanges[];
    createNewFile(oldFile: SourceFile | undefined, fileName: string, statements: readonly (Statement | SyntaxKind.NewLineTrivia)[]): void;
}
/** @internal */
export type ValidateNonFormattedText = (node: Node, text: string) => void;
/** @internal */
export declare function applyChanges(text: string, changes: readonly TextChange[]): string;
/** @internal */
export declare function assignPositionsToNode(node: Node): Node;
/** @internal */
export interface TextChangesWriter extends EmitTextWriter, PrintHandlers {
}
/** @internal */
export declare function createWriter(newLine: string): TextChangesWriter;
/** @internal */
export declare function isValidLocationToAddComment(sourceFile: SourceFile, position: number): boolean;
/**
 * Warning: This deletes comments too. See `copyComments` in `convertFunctionToEs6Class`.
 *
 * @internal
 */
export declare function deleteNode(changes: ChangeTracker, sourceFile: SourceFile, node: Node, options?: ConfigurableStartEnd): void;
//# sourceMappingURL=textChanges.d.ts.map