import { AssignmentExpression, AssignmentPattern, BinaryExpression, BinaryOperatorToken, BindingOrAssignmentElement, BindingOrAssignmentElementRestIndicator, BindingOrAssignmentElementTarget, BindingOrAssignmentPattern, Block, BooleanLiteral, CommaListExpression, CompilerOptions, ComputedPropertyName, DefaultKeyword, EmitHelperFactory, EmitHost, EmitResolver, EntityName, EqualsToken, ExclamationToken, ExportDeclaration, ExportKeyword, Expression, ForInitializer, GeneratedIdentifier, GeneratedNamePart, GeneratedPrivateIdentifier, GetAccessorDeclaration, HasIllegalDecorators, HasIllegalModifiers, HasIllegalType, HasIllegalTypeParameters, Identifier, ImportCall, ImportDeclaration, ImportEqualsDeclaration, JSDocNamespaceBody, JSDocTypeAssertion, JsxOpeningFragment, JsxOpeningLikeElement, LeftHandSideExpression, LiteralExpression, MemberExpression, MinusToken, Modifier, ModifiersArray, ModuleName, Node, NodeArray, NodeFactory, NullLiteral, ObjectLiteralElementLike, ObjectLiteralExpression, OuterExpression, OuterExpressionKinds, PlusToken, PostfixUnaryExpression, PrefixUnaryExpression, PrivateIdentifier, PropertyDeclaration, PropertyName, QuestionToken, ReadonlyKeyword, SetAccessorDeclaration, SourceFile, Statement, StringLiteral, SyntaxKind, TextRange, ThisTypeNode, Token, TypeNode } from "../_namespaces/ts";
/** @internal */
export declare function createEmptyExports(factory: NodeFactory): ExportDeclaration;
/** @internal */
export declare function createMemberAccessForPropertyName(factory: NodeFactory, target: Expression, memberName: PropertyName, location?: TextRange): MemberExpression;
/** @internal */
export declare function createJsxFactoryExpression(factory: NodeFactory, jsxFactoryEntity: EntityName | undefined, reactNamespace: string, parent: JsxOpeningLikeElement | JsxOpeningFragment): Expression;
/** @internal */
export declare function createExpressionForJsxElement(factory: NodeFactory, callee: Expression, tagName: Expression, props: Expression | undefined, children: readonly Expression[] | undefined, location: TextRange): LeftHandSideExpression;
/** @internal */
export declare function createExpressionForJsxFragment(factory: NodeFactory, jsxFactoryEntity: EntityName | undefined, jsxFragmentFactoryEntity: EntityName | undefined, reactNamespace: string, children: readonly Expression[], parentElement: JsxOpeningFragment, location: TextRange): LeftHandSideExpression;
/** @internal */
export declare function createForOfBindingStatement(factory: NodeFactory, node: ForInitializer, boundValue: Expression): Statement;
/** @internal */
export declare function insertLeadingStatement(factory: NodeFactory, dest: Statement, source: Statement): Block;
/** @internal */
export declare function createExpressionFromEntityName(factory: NodeFactory, node: EntityName | Expression): Expression;
/** @internal */
export declare function createExpressionForPropertyName(factory: NodeFactory, memberName: Exclude<PropertyName, PrivateIdentifier>): Expression;
/** @internal */
export declare function createExpressionForObjectLiteralElementLike(factory: NodeFactory, node: ObjectLiteralExpression, property: ObjectLiteralElementLike, receiver: Expression): Expression | undefined;
/**
 * Expand the read and increment/decrement operations a pre- or post-increment or pre- or post-decrement expression.
 *
 * ```ts
 * // input
 * <expression>++
 * // output (if result is not discarded)
 * var <temp>;
 * (<temp> = <expression>, <resultVariable> = <temp>++, <temp>)
 * // output (if result is discarded)
 * var <temp>;
 * (<temp> = <expression>, <temp>++, <temp>)
 *
 * // input
 * ++<expression>
 * // output (if result is not discarded)
 * var <temp>;
 * (<temp> = <expression>, <resultVariable> = ++<temp>)
 * // output (if result is discarded)
 * var <temp>;
 * (<temp> = <expression>, ++<temp>)
 * ```
 *
 * It is up to the caller to supply a temporary variable for `<resultVariable>` if one is needed.
 * The temporary variable `<temp>` is injected so that `++` and `--` work uniformly with `number` and `bigint`.
 * The result of the expression is always the final result of incrementing or decrementing the expression, so that it can be used for storage.
 *
 * @param factory {@link NodeFactory} used to create the expanded representation.
 * @param node The original prefix or postfix unary node.
 * @param expression The expression to use as the value to increment or decrement
 * @param resultVariable A temporary variable in which to store the result. Pass `undefined` if the result is discarded, or if the value of `<temp>` is the expected result.
 *
 * @internal
 */
export declare function expandPreOrPostfixIncrementOrDecrementExpression(factory: NodeFactory, node: PrefixUnaryExpression | PostfixUnaryExpression, expression: Expression, recordTempVariable: (node: Identifier) => void, resultVariable: Identifier | undefined): Expression;
/**
 * Gets whether an identifier should only be referred to by its internal name.
 *
 * @internal
 */
export declare function isInternalName(node: Identifier): boolean;
/**
 * Gets whether an identifier should only be referred to by its local name.
 *
 * @internal
 */
export declare function isLocalName(node: Identifier): boolean;
/**
 * Gets whether an identifier should only be referred to by its export representation if the
 * name points to an exported symbol.
 *
 * @internal
 */
export declare function isExportName(node: Identifier): boolean;
/** @internal */
export declare function findUseStrictPrologue(statements: readonly Statement[]): Statement | undefined;
/** @internal */
export declare function startsWithUseStrict(statements: readonly Statement[]): boolean;
/** @internal */
export declare function isCommaExpression(node: Expression): node is BinaryExpression & {
    operatorToken: Token<SyntaxKind.CommaToken>;
};
/** @internal */
export declare function isCommaSequence(node: Expression): node is BinaryExpression & {
    operatorToken: Token<SyntaxKind.CommaToken>;
} | CommaListExpression;
/** @internal */
export declare function isJSDocTypeAssertion(node: Node): node is JSDocTypeAssertion;
/** @internal */
export declare function getJSDocTypeAssertionType(node: JSDocTypeAssertion): TypeNode;
/** @internal */
export declare function isOuterExpression(node: Node, kinds?: OuterExpressionKinds): node is OuterExpression;
/** @internal */
export declare function skipOuterExpressions(node: Expression, kinds?: OuterExpressionKinds): Expression;
/** @internal */
export declare function skipOuterExpressions(node: Node, kinds?: OuterExpressionKinds): Node;
/** @internal */
export declare function walkUpOuterExpressions(node: Expression, kinds?: OuterExpressionKinds): Node;
/** @internal */
export declare function skipAssertions(node: Expression): Expression;
/** @internal */
export declare function skipAssertions(node: Node): Node;
/** @internal */
export declare function startOnNewLine<T extends Node>(node: T): T;
/** @internal */
export declare function getExternalHelpersModuleName(node: SourceFile): Identifier | undefined;
/** @internal */
export declare function hasRecordedExternalHelpers(sourceFile: SourceFile): boolean;
/** @internal */
export declare function createExternalHelpersImportDeclarationIfNeeded(nodeFactory: NodeFactory, helperFactory: EmitHelperFactory, sourceFile: SourceFile, compilerOptions: CompilerOptions, hasExportStarsToExportValues?: boolean, hasImportStar?: boolean, hasImportDefault?: boolean): ImportDeclaration | undefined;
/** @internal */
export declare function getOrCreateExternalHelpersModuleNameIfNeeded(factory: NodeFactory, node: SourceFile, compilerOptions: CompilerOptions, hasExportStarsToExportValues?: boolean, hasImportStarOrImportDefault?: boolean): Identifier | undefined;
/**
 * Get the name of that target module from an import or export declaration
 *
 * @internal
 */
export declare function getLocalNameForExternalImport(factory: NodeFactory, node: ImportDeclaration | ExportDeclaration | ImportEqualsDeclaration, sourceFile: SourceFile): Identifier | undefined;
/**
 * Get the name of a target module from an import/export declaration as should be written in the emitted output.
 * The emitted output name can be different from the input if:
 *  1. The module has a /// <amd-module name="<new name>" />
 *  2. --out or --outFile is used, making the name relative to the rootDir
 *  3- The containing SourceFile has an entry in renamedDependencies for the import as requested by some module loaders (e.g. System).
 * Otherwise, a new StringLiteral node representing the module name will be returned.
 *
 * @internal
 */
export declare function getExternalModuleNameLiteral(factory: NodeFactory, importNode: ImportDeclaration | ExportDeclaration | ImportEqualsDeclaration | ImportCall, sourceFile: SourceFile, host: EmitHost, resolver: EmitResolver, compilerOptions: CompilerOptions): StringLiteral | undefined;
/**
 * Get the name of a module as should be written in the emitted output.
 * The emitted output name can be different from the input if:
 *  1. The module has a /// <amd-module name="<new name>" />
 *  2. --out or --outFile is used, making the name relative to the rootDir
 * Otherwise, a new StringLiteral node representing the module name will be returned.
 *
 * @internal
 */
export declare function tryGetModuleNameFromFile(factory: NodeFactory, file: SourceFile | undefined, host: EmitHost, options: CompilerOptions): StringLiteral | undefined;
/**
 * Gets the initializer of an BindingOrAssignmentElement.
 *
 * @internal
 */
export declare function getInitializerOfBindingOrAssignmentElement(bindingElement: BindingOrAssignmentElement): Expression | undefined;
/**
 * Gets the name of an BindingOrAssignmentElement.
 *
 * @internal
 */
export declare function getTargetOfBindingOrAssignmentElement(bindingElement: BindingOrAssignmentElement): BindingOrAssignmentElementTarget | undefined;
/**
 * Determines whether an BindingOrAssignmentElement is a rest element.
 *
 * @internal
 */
export declare function getRestIndicatorOfBindingOrAssignmentElement(bindingElement: BindingOrAssignmentElement): BindingOrAssignmentElementRestIndicator | undefined;
/**
 * Gets the property name of a BindingOrAssignmentElement
 *
 * @internal
 */
export declare function getPropertyNameOfBindingOrAssignmentElement(bindingElement: BindingOrAssignmentElement): Exclude<PropertyName, PrivateIdentifier> | undefined;
/** @internal */
export declare function tryGetPropertyNameOfBindingOrAssignmentElement(bindingElement: BindingOrAssignmentElement): Exclude<PropertyName, PrivateIdentifier> | undefined;
/**
 * Gets the elements of a BindingOrAssignmentPattern
 *
 * @internal
 */
export declare function getElementsOfBindingOrAssignmentPattern(name: BindingOrAssignmentPattern): readonly BindingOrAssignmentElement[];
/** @internal */
export declare function getJSDocTypeAliasName(fullName: JSDocNamespaceBody | undefined): Identifier | undefined;
/** @internal */
export declare function canHaveIllegalType(node: Node): node is HasIllegalType;
/** @internal */
export declare function canHaveIllegalTypeParameters(node: Node): node is HasIllegalTypeParameters;
/** @internal */
export declare function canHaveIllegalDecorators(node: Node): node is HasIllegalDecorators;
/** @internal */
export declare function canHaveIllegalModifiers(node: Node): node is HasIllegalModifiers;
export declare function isQuestionOrExclamationToken(node: Node): node is QuestionToken | ExclamationToken;
export declare function isIdentifierOrThisTypeNode(node: Node): node is Identifier | ThisTypeNode;
export declare function isReadonlyKeywordOrPlusOrMinusToken(node: Node): node is ReadonlyKeyword | PlusToken | MinusToken;
export declare function isQuestionOrPlusOrMinusToken(node: Node): node is QuestionToken | PlusToken | MinusToken;
export declare function isModuleName(node: Node): node is ModuleName;
/** @internal */
export declare function isLiteralTypeLikeExpression(node: Node): node is NullLiteral | BooleanLiteral | LiteralExpression | PrefixUnaryExpression;
export declare function isBinaryOperatorToken(node: Node): node is BinaryOperatorToken;
/**
 * Creates a state machine that walks a `BinaryExpression` using the heap to reduce call-stack depth on a large tree.
 * @param onEnter Callback evaluated when entering a `BinaryExpression`. Returns new user-defined state to associate with the node while walking.
 * @param onLeft Callback evaluated when walking the left side of a `BinaryExpression`. Return a `BinaryExpression` to continue walking, or `void` to advance to the right side.
 * @param onRight Callback evaluated when walking the right side of a `BinaryExpression`. Return a `BinaryExpression` to continue walking, or `void` to advance to the end of the node.
 * @param onExit Callback evaluated when exiting a `BinaryExpression`. The result returned will either be folded into the parent's state, or returned from the walker if at the top frame.
 * @param foldState Callback evaluated when the result from a nested `onExit` should be folded into the state of that node's parent.
 * @returns A function that walks a `BinaryExpression` node using the above callbacks, returning the result of the call to `onExit` from the outermost `BinaryExpression` node.
 *
 * @internal
 */
export declare function createBinaryExpressionTrampoline<TState, TResult>(onEnter: (node: BinaryExpression, prev: TState | undefined) => TState, onLeft: ((left: Expression, userState: TState, node: BinaryExpression) => BinaryExpression | void) | undefined, onOperator: ((operatorToken: BinaryOperatorToken, userState: TState, node: BinaryExpression) => void) | undefined, onRight: ((right: Expression, userState: TState, node: BinaryExpression) => BinaryExpression | void) | undefined, onExit: (node: BinaryExpression, userState: TState) => TResult, foldState: ((userState: TState, result: TResult, side: "left" | "right") => TState) | undefined): (node: BinaryExpression) => TResult;
/**
 * Creates a state machine that walks a `BinaryExpression` using the heap to reduce call-stack depth on a large tree.
 * @param onEnter Callback evaluated when entering a `BinaryExpression`. Returns new user-defined state to associate with the node while walking.
 * @param onLeft Callback evaluated when walking the left side of a `BinaryExpression`. Return a `BinaryExpression` to continue walking, or `void` to advance to the right side.
 * @param onRight Callback evaluated when walking the right side of a `BinaryExpression`. Return a `BinaryExpression` to continue walking, or `void` to advance to the end of the node.
 * @param onExit Callback evaluated when exiting a `BinaryExpression`. The result returned will either be folded into the parent's state, or returned from the walker if at the top frame.
 * @param foldState Callback evaluated when the result from a nested `onExit` should be folded into the state of that node's parent.
 * @returns A function that walks a `BinaryExpression` node using the above callbacks, returning the result of the call to `onExit` from the outermost `BinaryExpression` node.
 *
 * @internal
 */
export declare function createBinaryExpressionTrampoline<TOuterState, TState, TResult>(onEnter: (node: BinaryExpression, prev: TState | undefined, outerState: TOuterState) => TState, onLeft: ((left: Expression, userState: TState, node: BinaryExpression) => BinaryExpression | void) | undefined, onOperator: ((operatorToken: BinaryOperatorToken, userState: TState, node: BinaryExpression) => void) | undefined, onRight: ((right: Expression, userState: TState, node: BinaryExpression) => BinaryExpression | void) | undefined, onExit: (node: BinaryExpression, userState: TState) => TResult, foldState: ((userState: TState, result: TResult, side: "left" | "right") => TState) | undefined): (node: BinaryExpression, outerState: TOuterState) => TResult;
/** @internal */
export declare function isExportOrDefaultModifier(node: Node): node is ExportKeyword | DefaultKeyword;
/** @internal */
export declare function isNonExportDefaultModifier(node: Node): node is Exclude<Modifier, ExportKeyword | DefaultKeyword>;
/**
 * If `nodes` is not undefined, creates an empty `NodeArray` that preserves the `pos` and `end` of `nodes`.
 * @internal
 */
export declare function elideNodes<T extends Node>(factory: NodeFactory, nodes: NodeArray<T>): NodeArray<T>;
/** @internal */
export declare function elideNodes<T extends Node>(factory: NodeFactory, nodes: NodeArray<T> | undefined): NodeArray<T> | undefined;
/**
 * Gets the node from which a name should be generated.
 *
 * @internal
 */
export declare function getNodeForGeneratedName(name: GeneratedIdentifier | GeneratedPrivateIdentifier): Node | GeneratedIdentifier | GeneratedPrivateIdentifier;
/**
 * Formats a prefix or suffix of a generated name.
 *
 * @internal
 */
export declare function formatGeneratedNamePart(part: string | undefined): string;
/**
 * Formats a prefix or suffix of a generated name. If the part is a {@link GeneratedNamePart}, calls {@link generateName} to format the source node.
 *
 * @internal
 */
export declare function formatGeneratedNamePart(part: string | GeneratedNamePart | undefined, generateName: (name: GeneratedIdentifier | GeneratedPrivateIdentifier) => string): string;
/**
 * Formats a generated name.
 * @param privateName When `true`, inserts a `#` character at the start of the result.
 * @param prefix The prefix (if any) to include before the base name.
 * @param baseName The base name for the generated name.
 * @param suffix The suffix (if any) to include after the base name.
 *
 * @internal
 */
export declare function formatGeneratedName(privateName: boolean, prefix: string | undefined, baseName: string, suffix: string | undefined): string;
/**
 * Formats a generated name.
 * @param privateName When `true`, inserts a `#` character at the start of the result.
 * @param prefix The prefix (if any) to include before the base name.
 * @param baseName The base name for the generated name.
 * @param suffix The suffix (if any) to include after the base name.
 * @param generateName Called to format the source node of {@link prefix} when it is a {@link GeneratedNamePart}.
 *
 * @internal
 */
export declare function formatGeneratedName(privateName: boolean, prefix: string | GeneratedNamePart | undefined, baseName: string | Identifier | PrivateIdentifier, suffix: string | GeneratedNamePart | undefined, generateName: (name: GeneratedIdentifier | GeneratedPrivateIdentifier) => string): string;
/**
 * Creates a private backing field for an `accessor` {@link PropertyDeclaration}.
 *
 * @internal
 */
export declare function createAccessorPropertyBackingField(factory: NodeFactory, node: PropertyDeclaration, modifiers: ModifiersArray | undefined, initializer: Expression | undefined): PropertyDeclaration;
/**
 * Creates a {@link GetAccessorDeclaration} that reads from a private backing field.
 *
 * @internal
 */
export declare function createAccessorPropertyGetRedirector(factory: NodeFactory, node: PropertyDeclaration, modifiers: ModifiersArray | undefined, name: PropertyName): GetAccessorDeclaration;
/**
 * Creates a {@link SetAccessorDeclaration} that writes to a private backing field.
 *
 * @internal
 */
export declare function createAccessorPropertySetRedirector(factory: NodeFactory, node: PropertyDeclaration, modifiers: ModifiersArray | undefined, name: PropertyName): SetAccessorDeclaration;
/** @internal */
export declare function findComputedPropertyNameCacheAssignment(name: ComputedPropertyName): (AssignmentExpression<EqualsToken> & {
    readonly left: GeneratedIdentifier;
}) | undefined;
/**
 * Flatten a CommaExpression or CommaListExpression into an array of one or more expressions, unwrapping any nested
 * comma expressions and synthetic parens.
 *
 * @internal
 */
export declare function flattenCommaList(node: Expression): Expression[];
/**
 * Walk an AssignmentPattern to determine if it contains object rest (`...`) syntax. We cannot rely on
 * propagation of `TransformFlags.ContainsObjectRestOrSpread` since it isn't propagated by default in
 * ObjectLiteralExpression and ArrayLiteralExpression since we do not know whether they belong to an
 * AssignmentPattern at the time the nodes are parsed.
 *
 * @internal
 */
export declare function containsObjectRestOrSpread(node: AssignmentPattern): boolean;
//# sourceMappingURL=utilities.d.ts.map