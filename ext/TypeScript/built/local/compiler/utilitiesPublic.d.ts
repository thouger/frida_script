import { __String, AccessorDeclaration, ArrayBindingElement, ArrayBindingOrAssignmentElement, ArrayBindingOrAssignmentPattern, AssertionExpression, AssertionKey, AssignmentPattern, AutoAccessorPropertyDeclaration, BindingElement, BindingName, BindingOrAssignmentElement, BindingOrAssignmentElementTarget, BindingOrAssignmentPattern, BindingPattern, Block, BooleanLiteral, BreakOrContinueStatement, CallChain, CallExpression, CallLikeExpression, CaseOrDefaultClause, ClassElement, ClassLikeDeclaration, ClassStaticBlockDeclaration, CompilerOptions, ConciseBody, ConstructorDeclaration, ConstructorTypeNode, Declaration, DeclarationName, DeclarationStatement, DeclarationWithTypeParameters, Decorator, Diagnostic, ElementAccessChain, EntityName, EnumDeclaration, ExportSpecifier, Expression, FileReference, ForInitializer, ForInOrOfStatement, FunctionBody, FunctionLikeDeclaration, FunctionTypeNode, GeneratedIdentifier, GeneratedPrivateIdentifier, GetAccessorDeclaration, HasDecorators, HasExpressionInitializer, HasInitializer, HasJSDoc, HasLocals, HasModifiers, HasType, Identifier, ImportSpecifier, ImportTypeNode, IterationStatement, JSDocAugmentsTag, JSDocClassTag, JSDocComment, JSDocDeprecatedTag, JSDocEnumTag, JSDocImplementsTag, JSDocLink, JSDocLinkCode, JSDocLinkPlain, JSDocNamespaceBody, JSDocOverrideTag, JSDocParameterTag, JSDocPrivateTag, JSDocPropertyLikeTag, JSDocProtectedTag, JSDocPublicTag, JSDocReadonlyTag, JSDocReturnTag, JSDocSatisfiesTag, JSDocSignature, JSDocTag, JSDocTemplateTag, JSDocThisTag, JSDocTypedefTag, JSDocTypeTag, JsxAttributeLike, JsxChild, JsxExpression, JsxOpeningLikeElement, JsxTagNameExpression, KeywordSyntaxKind, LabeledStatement, LeftHandSideExpression, LiteralExpression, LiteralToken, MemberName, MethodDeclaration, Modifier, ModifierFlags, ModifierLike, ModuleBody, ModuleDeclaration, ModuleReference, NamedDeclaration, NamedExportBindings, NamedImportBindings, NamespaceBody, NewExpression, Node, NodeArray, NodeFlags, NonNullChain, NotEmittedStatement, NullLiteral, ObjectBindingOrAssignmentElement, ObjectBindingOrAssignmentPattern, ObjectLiteralElement, ObjectLiteralElementLike, OptionalChain, OptionalChainRoot, ParameterDeclaration, PartiallyEmittedExpression, PostfixUnaryExpression, PrefixUnaryExpression, PrivateClassElementDeclaration, PrivateIdentifier, PrivateIdentifierPropertyAccessExpression, PropertyAccessChain, PropertyAccessExpression, PropertyDeclaration, PropertyName, QualifiedName, SetAccessorDeclaration, SignatureDeclaration, SortedReadonlyArray, Statement, StringLiteral, StringLiteralLike, Symbol, SyntaxKind, TemplateLiteral, TemplateLiteralToken, TemplateMiddle, TemplateTail, TextChangeRange, TextRange, TextSpan, TypeElement, TypeNode, TypeOnlyAliasDeclaration, TypeOnlyExportDeclaration, TypeOnlyImportDeclaration, TypeParameterDeclaration, TypeReferenceType, UnaryExpression, UnparsedNode, UnparsedTextLike, VariableDeclaration } from "./_namespaces/ts";
export declare function isExternalModuleNameRelative(moduleName: string): boolean;
export declare function sortAndDeduplicateDiagnostics<T extends Diagnostic>(diagnostics: readonly T[]): SortedReadonlyArray<T>;
export declare function getDefaultLibFileName(options: CompilerOptions): string;
export declare function textSpanEnd(span: TextSpan): number;
export declare function textSpanIsEmpty(span: TextSpan): boolean;
export declare function textSpanContainsPosition(span: TextSpan, position: number): boolean;
/** @internal */
export declare function textRangeContainsPositionInclusive(span: TextRange, position: number): boolean;
export declare function textSpanContainsTextSpan(span: TextSpan, other: TextSpan): boolean;
export declare function textSpanOverlapsWith(span: TextSpan, other: TextSpan): boolean;
export declare function textSpanOverlap(span1: TextSpan, span2: TextSpan): TextSpan | undefined;
export declare function textSpanIntersectsWithTextSpan(span: TextSpan, other: TextSpan): boolean;
export declare function textSpanIntersectsWith(span: TextSpan, start: number, length: number): boolean;
export declare function decodedTextSpanIntersectsWith(start1: number, length1: number, start2: number, length2: number): boolean;
export declare function textSpanIntersectsWithPosition(span: TextSpan, position: number): boolean;
export declare function textSpanIntersection(span1: TextSpan, span2: TextSpan): TextSpan | undefined;
export declare function createTextSpan(start: number, length: number): TextSpan;
export declare function createTextSpanFromBounds(start: number, end: number): TextSpan;
export declare function textChangeRangeNewSpan(range: TextChangeRange): TextSpan;
export declare function textChangeRangeIsUnchanged(range: TextChangeRange): boolean;
export declare function createTextChangeRange(span: TextSpan, newLength: number): TextChangeRange;
export declare let unchangedTextChangeRange: TextChangeRange;
/**
 * Called to merge all the changes that occurred across several versions of a script snapshot
 * into a single change.  i.e. if a user keeps making successive edits to a script we will
 * have a text change from V1 to V2, V2 to V3, ..., Vn.
 *
 * This function will then merge those changes into a single change range valid between V1 and
 * Vn.
 */
export declare function collapseTextChangeRangesAcrossMultipleVersions(changes: readonly TextChangeRange[]): TextChangeRange;
export declare function getTypeParameterOwner(d: Declaration): Declaration | undefined;
export type ParameterPropertyDeclaration = ParameterDeclaration & {
    parent: ConstructorDeclaration;
    name: Identifier;
};
export declare function isParameterPropertyDeclaration(node: Node, parent: Node): node is ParameterPropertyDeclaration;
export declare function isEmptyBindingPattern(node: BindingName): node is BindingPattern;
export declare function isEmptyBindingElement(node: BindingElement | ArrayBindingElement): boolean;
export declare function walkUpBindingElementsAndPatterns(binding: BindingElement): VariableDeclaration | ParameterDeclaration;
export declare function getCombinedModifierFlags(node: Declaration): ModifierFlags;
/** @internal */
export declare function getCombinedNodeFlagsAlwaysIncludeJSDoc(node: Declaration): ModifierFlags;
export declare function getCombinedNodeFlags(node: Node): NodeFlags;
/** @internal */
export declare const supportedLocaleDirectories: string[];
/**
 * Checks to see if the locale is in the appropriate format,
 * and if it is, attempts to set the appropriate language.
 */
export declare function validateLocaleAndSetLanguage(locale: string, sys: {
    getExecutingFilePath(): string;
    resolvePath(path: string): string;
    fileExists(fileName: string): boolean;
    readFile(fileName: string): string | undefined;
}, errors?: Diagnostic[]): void;
export declare function getOriginalNode(node: Node): Node;
export declare function getOriginalNode<T extends Node>(node: Node, nodeTest: (node: Node) => node is T): T;
export declare function getOriginalNode(node: Node | undefined): Node | undefined;
export declare function getOriginalNode<T extends Node>(node: Node | undefined, nodeTest: (node: Node) => node is T): T | undefined;
/**
 * Iterates through the parent chain of a node and performs the callback on each parent until the callback
 * returns a truthy value, then returns that value.
 * If no such value is found, it applies the callback until the parent pointer is undefined or the callback returns "quit"
 * At that point findAncestor returns undefined.
 */
export declare function findAncestor<T extends Node>(node: Node | undefined, callback: (element: Node) => element is T): T | undefined;
export declare function findAncestor(node: Node | undefined, callback: (element: Node) => boolean | "quit"): Node | undefined;
/**
 * Gets a value indicating whether a node originated in the parse tree.
 *
 * @param node The node to test.
 */
export declare function isParseTreeNode(node: Node): boolean;
/**
 * Gets the original parse tree node for a node.
 *
 * @param node The original node.
 * @returns The original parse tree node if found; otherwise, undefined.
 */
export declare function getParseTreeNode(node: Node | undefined): Node | undefined;
/**
 * Gets the original parse tree node for a node.
 *
 * @param node The original node.
 * @param nodeTest A callback used to ensure the correct type of parse tree node is returned.
 * @returns The original parse tree node if found; otherwise, undefined.
 */
export declare function getParseTreeNode<T extends Node>(node: T | undefined, nodeTest?: (node: Node) => node is T): T | undefined;
/** Add an extra underscore to identifiers that start with two underscores to avoid issues with magic names like '__proto__' */
export declare function escapeLeadingUnderscores(identifier: string): __String;
/**
 * Remove extra underscore from escaped identifier text content.
 *
 * @param identifier The escaped identifier text.
 * @returns The unescaped identifier text.
 */
export declare function unescapeLeadingUnderscores(identifier: __String): string;
export declare function idText(identifierOrPrivateName: Identifier | PrivateIdentifier): string;
/**
 * If the text of an Identifier matches a keyword (including contextual and TypeScript-specific keywords), returns the
 * SyntaxKind for the matching keyword.
 */
export declare function identifierToKeywordKind(node: Identifier): KeywordSyntaxKind | undefined;
export declare function symbolName(symbol: Symbol): string;
/** @internal */
export declare function nodeHasName(statement: Node, name: Identifier): boolean;
export declare function getNameOfJSDocTypedef(declaration: JSDocTypedefTag): Identifier | PrivateIdentifier | undefined;
/** @internal */
export declare function isNamedDeclaration(node: Node): node is NamedDeclaration & {
    name: DeclarationName;
};
/** @internal */
export declare function getNonAssignedNameOfDeclaration(declaration: Declaration | Expression): DeclarationName | undefined;
export declare function getNameOfDeclaration(declaration: Declaration | Expression | undefined): DeclarationName | undefined;
/** @internal */
export declare function getAssignedName(node: Node): DeclarationName | undefined;
export declare function getDecorators(node: HasDecorators): readonly Decorator[] | undefined;
export declare function getModifiers(node: HasModifiers): readonly Modifier[] | undefined;
/**
 * Gets the JSDoc parameter tags for the node if present.
 *
 * @remarks Returns any JSDoc param tag whose name matches the provided
 * parameter, whether a param tag on a containing function
 * expression, or a param tag on a variable declaration whose
 * initializer is the containing function. The tags closest to the
 * node are returned first, so in the previous example, the param
 * tag on the containing function expression would be first.
 *
 * For binding patterns, parameter tags are matched by position.
 */
export declare function getJSDocParameterTags(param: ParameterDeclaration): readonly JSDocParameterTag[];
/** @internal */
export declare function getJSDocParameterTagsNoCache(param: ParameterDeclaration): readonly JSDocParameterTag[];
/**
 * Gets the JSDoc type parameter tags for the node if present.
 *
 * @remarks Returns any JSDoc template tag whose names match the provided
 * parameter, whether a template tag on a containing function
 * expression, or a template tag on a variable declaration whose
 * initializer is the containing function. The tags closest to the
 * node are returned first, so in the previous example, the template
 * tag on the containing function expression would be first.
 */
export declare function getJSDocTypeParameterTags(param: TypeParameterDeclaration): readonly JSDocTemplateTag[];
/** @internal */
export declare function getJSDocTypeParameterTagsNoCache(param: TypeParameterDeclaration): readonly JSDocTemplateTag[];
/**
 * Return true if the node has JSDoc parameter tags.
 *
 * @remarks Includes parameter tags that are not directly on the node,
 * for example on a variable declaration whose initializer is a function expression.
 */
export declare function hasJSDocParameterTags(node: FunctionLikeDeclaration | SignatureDeclaration): boolean;
/** Gets the JSDoc augments tag for the node if present */
export declare function getJSDocAugmentsTag(node: Node): JSDocAugmentsTag | undefined;
/** Gets the JSDoc implements tags for the node if present */
export declare function getJSDocImplementsTags(node: Node): readonly JSDocImplementsTag[];
/** Gets the JSDoc class tag for the node if present */
export declare function getJSDocClassTag(node: Node): JSDocClassTag | undefined;
/** Gets the JSDoc public tag for the node if present */
export declare function getJSDocPublicTag(node: Node): JSDocPublicTag | undefined;
/** @internal */
export declare function getJSDocPublicTagNoCache(node: Node): JSDocPublicTag | undefined;
/** Gets the JSDoc private tag for the node if present */
export declare function getJSDocPrivateTag(node: Node): JSDocPrivateTag | undefined;
/** @internal */
export declare function getJSDocPrivateTagNoCache(node: Node): JSDocPrivateTag | undefined;
/** Gets the JSDoc protected tag for the node if present */
export declare function getJSDocProtectedTag(node: Node): JSDocProtectedTag | undefined;
/** @internal */
export declare function getJSDocProtectedTagNoCache(node: Node): JSDocProtectedTag | undefined;
/** Gets the JSDoc protected tag for the node if present */
export declare function getJSDocReadonlyTag(node: Node): JSDocReadonlyTag | undefined;
/** @internal */
export declare function getJSDocReadonlyTagNoCache(node: Node): JSDocReadonlyTag | undefined;
export declare function getJSDocOverrideTagNoCache(node: Node): JSDocOverrideTag | undefined;
/** Gets the JSDoc deprecated tag for the node if present */
export declare function getJSDocDeprecatedTag(node: Node): JSDocDeprecatedTag | undefined;
/** @internal */
export declare function getJSDocDeprecatedTagNoCache(node: Node): JSDocDeprecatedTag | undefined;
/** Gets the JSDoc enum tag for the node if present */
export declare function getJSDocEnumTag(node: Node): JSDocEnumTag | undefined;
/** Gets the JSDoc this tag for the node if present */
export declare function getJSDocThisTag(node: Node): JSDocThisTag | undefined;
/** Gets the JSDoc return tag for the node if present */
export declare function getJSDocReturnTag(node: Node): JSDocReturnTag | undefined;
/** Gets the JSDoc template tag for the node if present */
export declare function getJSDocTemplateTag(node: Node): JSDocTemplateTag | undefined;
export declare function getJSDocSatisfiesTag(node: Node): JSDocSatisfiesTag | undefined;
/** Gets the JSDoc type tag for the node if present and valid */
export declare function getJSDocTypeTag(node: Node): JSDocTypeTag | undefined;
/**
 * Gets the type node for the node if provided via JSDoc.
 *
 * @remarks The search includes any JSDoc param tag that relates
 * to the provided parameter, for example a type tag on the
 * parameter itself, or a param tag on a containing function
 * expression, or a param tag on a variable declaration whose
 * initializer is the containing function. The tags closest to the
 * node are examined first, so in the previous example, the type
 * tag directly on the node would be returned.
 */
export declare function getJSDocType(node: Node): TypeNode | undefined;
/**
 * Gets the return type node for the node if provided via JSDoc return tag or type tag.
 *
 * @remarks `getJSDocReturnTag` just gets the whole JSDoc tag. This function
 * gets the type from inside the braces, after the fat arrow, etc.
 */
export declare function getJSDocReturnType(node: Node): TypeNode | undefined;
/** Get all JSDoc tags related to a node, including those on parent nodes. */
export declare function getJSDocTags(node: Node): readonly JSDocTag[];
/** @internal */
export declare function getJSDocTagsNoCache(node: Node): readonly JSDocTag[];
/** Gets all JSDoc tags that match a specified predicate */
export declare function getAllJSDocTags<T extends JSDocTag>(node: Node, predicate: (tag: JSDocTag) => tag is T): readonly T[];
/** Gets all JSDoc tags of a specified kind */
export declare function getAllJSDocTagsOfKind(node: Node, kind: SyntaxKind): readonly JSDocTag[];
/** Gets the text of a jsdoc comment, flattening links to their text. */
export declare function getTextOfJSDocComment(comment?: string | NodeArray<JSDocComment>): string | undefined;
/**
 * Gets the effective type parameters. If the node was parsed in a
 * JavaScript file, gets the type parameters from the `@template` tag from JSDoc.
 *
 * This does *not* return type parameters from a jsdoc reference to a generic type, eg
 *
 * type Id = <T>(x: T) => T
 * /** @type {Id} /
 * function id(x) { return x }
 */
export declare function getEffectiveTypeParameterDeclarations(node: DeclarationWithTypeParameters): readonly TypeParameterDeclaration[];
export declare function getEffectiveConstraintOfTypeParameter(node: TypeParameterDeclaration): TypeNode | undefined;
export declare function isMemberName(node: Node): node is MemberName;
/** @internal */
export declare function isGetOrSetAccessorDeclaration(node: Node): node is AccessorDeclaration;
export declare function isPropertyAccessChain(node: Node): node is PropertyAccessChain;
export declare function isElementAccessChain(node: Node): node is ElementAccessChain;
export declare function isCallChain(node: Node): node is CallChain;
export declare function isOptionalChain(node: Node): node is PropertyAccessChain | ElementAccessChain | CallChain | NonNullChain;
/** @internal */
export declare function isOptionalChainRoot(node: Node): node is OptionalChainRoot;
/**
 * Determines whether a node is the expression preceding an optional chain (i.e. `a` in `a?.b`).
 *
 * @internal
 */
export declare function isExpressionOfOptionalChainRoot(node: Node): node is Expression & {
    parent: OptionalChainRoot;
};
/**
 * Determines whether a node is the outermost `OptionalChain` in an ECMAScript `OptionalExpression`:
 *
 * 1. For `a?.b.c`, the outermost chain is `a?.b.c` (`c` is the end of the chain starting at `a?.`)
 * 2. For `a?.b!`, the outermost chain is `a?.b` (`b` is the end of the chain starting at `a?.`)
 * 3. For `(a?.b.c).d`, the outermost chain is `a?.b.c` (`c` is the end of the chain starting at `a?.` since parens end the chain)
 * 4. For `a?.b.c?.d`, both `a?.b.c` and `a?.b.c?.d` are outermost (`c` is the end of the chain starting at `a?.`, and `d` is
 *   the end of the chain starting at `c?.`)
 * 5. For `a?.(b?.c).d`, both `b?.c` and `a?.(b?.c)d` are outermost (`c` is the end of the chain starting at `b`, and `d` is
 *   the end of the chain starting at `a?.`)
 *
 * @internal
 */
export declare function isOutermostOptionalChain(node: OptionalChain): boolean;
export declare function isNullishCoalesce(node: Node): boolean;
export declare function isConstTypeReference(node: Node): boolean;
export declare function skipPartiallyEmittedExpressions(node: Expression): Expression;
export declare function skipPartiallyEmittedExpressions(node: Node): Node;
export declare function isNonNullChain(node: Node): node is NonNullChain;
export declare function isBreakOrContinueStatement(node: Node): node is BreakOrContinueStatement;
export declare function isNamedExportBindings(node: Node): node is NamedExportBindings;
/** @deprecated */
export declare function isUnparsedTextLike(node: Node): node is UnparsedTextLike;
/** @deprecated */
export declare function isUnparsedNode(node: Node): node is UnparsedNode;
export declare function isJSDocPropertyLikeTag(node: Node): node is JSDocPropertyLikeTag;
/** @internal */
export declare function isNode(node: Node): boolean;
/** @internal */
export declare function isNodeKind(kind: SyntaxKind): boolean;
/**
 * True if kind is of some token syntax kind.
 * For example, this is true for an IfKeyword but not for an IfStatement.
 * Literals are considered tokens, except TemplateLiteral, but does include TemplateHead/Middle/Tail.
 */
export declare function isTokenKind(kind: SyntaxKind): boolean;
/**
 * True if node is of some token syntax kind.
 * For example, this is true for an IfKeyword but not for an IfStatement.
 * Literals are considered tokens, except TemplateLiteral, but does include TemplateHead/Middle/Tail.
 */
export declare function isToken(n: Node): boolean;
/** @internal */
export declare function isNodeArray<T extends Node>(array: readonly T[]): array is NodeArray<T>;
/** @internal */
export declare function isLiteralKind(kind: SyntaxKind): kind is LiteralToken["kind"];
export declare function isLiteralExpression(node: Node): node is LiteralExpression;
/** @internal */
export declare function isLiteralExpressionOfObject(node: Node): boolean;
/** @internal */
export declare function isTemplateLiteralKind(kind: SyntaxKind): kind is TemplateLiteralToken["kind"];
export declare function isTemplateLiteralToken(node: Node): node is TemplateLiteralToken;
export declare function isTemplateMiddleOrTemplateTail(node: Node): node is TemplateMiddle | TemplateTail;
export declare function isImportOrExportSpecifier(node: Node): node is ImportSpecifier | ExportSpecifier;
export declare function isTypeOnlyImportDeclaration(node: Node): node is TypeOnlyImportDeclaration;
export declare function isTypeOnlyExportDeclaration(node: Node): node is TypeOnlyExportDeclaration;
export declare function isTypeOnlyImportOrExportDeclaration(node: Node): node is TypeOnlyAliasDeclaration;
export declare function isAssertionKey(node: Node): node is AssertionKey;
export declare function isStringTextContainingNode(node: Node): node is StringLiteral | TemplateLiteralToken;
/** @internal */
export declare function isGeneratedIdentifier(node: Node): node is GeneratedIdentifier;
/** @internal */
export declare function isGeneratedPrivateIdentifier(node: Node): node is GeneratedPrivateIdentifier;
/** @internal */
export declare function isPrivateIdentifierClassElementDeclaration(node: Node): node is PrivateClassElementDeclaration;
/** @internal */
export declare function isPrivateIdentifierPropertyAccessExpression(node: Node): node is PrivateIdentifierPropertyAccessExpression;
/** @internal */
export declare function isModifierKind(token: SyntaxKind): token is Modifier["kind"];
/** @internal */
export declare function isParameterPropertyModifier(kind: SyntaxKind): boolean;
/** @internal */
export declare function isClassMemberModifier(idToken: SyntaxKind): boolean;
export declare function isModifier(node: Node): node is Modifier;
export declare function isEntityName(node: Node): node is EntityName;
export declare function isPropertyName(node: Node): node is PropertyName;
export declare function isBindingName(node: Node): node is BindingName;
export declare function isFunctionLike(node: Node | undefined): node is SignatureDeclaration;
/** @internal */
export declare function isFunctionLikeOrClassStaticBlockDeclaration(node: Node | undefined): node is SignatureDeclaration | ClassStaticBlockDeclaration;
/** @internal */
export declare function isFunctionLikeDeclaration(node: Node): node is FunctionLikeDeclaration;
/** @internal */
export declare function isBooleanLiteral(node: Node): node is BooleanLiteral;
/** @internal */
export declare function isFunctionLikeKind(kind: SyntaxKind): boolean;
/** @internal */
export declare function isFunctionOrModuleBlock(node: Node): boolean;
export declare function isClassElement(node: Node): node is ClassElement;
export declare function isClassLike(node: Node): node is ClassLikeDeclaration;
export declare function isAccessor(node: Node): node is AccessorDeclaration;
export declare function isAutoAccessorPropertyDeclaration(node: Node): node is AutoAccessorPropertyDeclaration;
/** @internal */
export declare function isMethodOrAccessor(node: Node): node is MethodDeclaration | AccessorDeclaration;
/** @internal */
export declare function isNamedClassElement(node: Node): node is MethodDeclaration | AccessorDeclaration | PropertyDeclaration;
export declare function isModifierLike(node: Node): node is ModifierLike;
export declare function isTypeElement(node: Node): node is TypeElement;
export declare function isClassOrTypeElement(node: Node): node is ClassElement | TypeElement;
export declare function isObjectLiteralElementLike(node: Node): node is ObjectLiteralElementLike;
/**
 * Node test that determines whether a node is a valid type node.
 * This differs from the `isPartOfTypeNode` function which determines whether a node is *part*
 * of a TypeNode.
 */
export declare function isTypeNode(node: Node): node is TypeNode;
export declare function isFunctionOrConstructorTypeNode(node: Node): node is FunctionTypeNode | ConstructorTypeNode;
/** @internal */
export declare function isBindingPattern(node: Node | undefined): node is BindingPattern;
/** @internal */
export declare function isAssignmentPattern(node: Node): node is AssignmentPattern;
export declare function isArrayBindingElement(node: Node): node is ArrayBindingElement;
/**
 * Determines whether the BindingOrAssignmentElement is a BindingElement-like declaration
 *
 * @internal
 */
export declare function isDeclarationBindingElement(bindingElement: BindingOrAssignmentElement): bindingElement is VariableDeclaration | ParameterDeclaration | BindingElement;
/** @internal */
export declare function isBindingOrAssignmentElement(node: Node): node is BindingOrAssignmentElement;
/**
 * Determines whether a node is a BindingOrAssignmentPattern
 *
 * @internal
 */
export declare function isBindingOrAssignmentPattern(node: BindingOrAssignmentElementTarget): node is BindingOrAssignmentPattern;
/**
 * Determines whether a node is an ObjectBindingOrAssignmentPattern
 *
 * @internal
 */
export declare function isObjectBindingOrAssignmentPattern(node: BindingOrAssignmentElementTarget): node is ObjectBindingOrAssignmentPattern;
/** @internal */
export declare function isObjectBindingOrAssignmentElement(node: Node): node is ObjectBindingOrAssignmentElement;
/**
 * Determines whether a node is an ArrayBindingOrAssignmentPattern
 *
 * @internal
 */
export declare function isArrayBindingOrAssignmentPattern(node: BindingOrAssignmentElementTarget): node is ArrayBindingOrAssignmentPattern;
/** @internal */
export declare function isArrayBindingOrAssignmentElement(node: Node): node is ArrayBindingOrAssignmentElement;
/** @internal */
export declare function isPropertyAccessOrQualifiedNameOrImportTypeNode(node: Node): node is PropertyAccessExpression | QualifiedName | ImportTypeNode;
export declare function isPropertyAccessOrQualifiedName(node: Node): node is PropertyAccessExpression | QualifiedName;
export declare function isCallLikeExpression(node: Node): node is CallLikeExpression;
export declare function isCallOrNewExpression(node: Node): node is CallExpression | NewExpression;
export declare function isTemplateLiteral(node: Node): node is TemplateLiteral;
export declare function isLeftHandSideExpression(node: Node): node is LeftHandSideExpression;
/** @internal */
export declare function isUnaryExpression(node: Node): node is UnaryExpression;
/** @internal */
export declare function isUnaryExpressionWithWrite(expr: Node): expr is PrefixUnaryExpression | PostfixUnaryExpression;
export declare function isLiteralTypeLiteral(node: Node): node is NullLiteral | BooleanLiteral | LiteralExpression | PrefixUnaryExpression;
/**
 * Determines whether a node is an expression based only on its kind.
 */
export declare function isExpression(node: Node): node is Expression;
export declare function isAssertionExpression(node: Node): node is AssertionExpression;
/** @internal */
export declare function isNotEmittedOrPartiallyEmittedNode(node: Node): node is NotEmittedStatement | PartiallyEmittedExpression;
export declare function isIterationStatement(node: Node, lookInLabeledStatements: false): node is IterationStatement;
export declare function isIterationStatement(node: Node, lookInLabeledStatements: boolean): node is IterationStatement | LabeledStatement;
/** @internal */
export declare function isScopeMarker(node: Node): boolean;
/** @internal */
export declare function hasScopeMarker(statements: readonly Statement[]): boolean;
/** @internal */
export declare function needsScopeMarker(result: Statement): boolean;
/** @internal */
export declare function isExternalModuleIndicator(result: Statement): boolean;
/** @internal */
export declare function isForInOrOfStatement(node: Node): node is ForInOrOfStatement;
export declare function isConciseBody(node: Node): node is ConciseBody;
/** @internal */
export declare function isFunctionBody(node: Node): node is FunctionBody;
export declare function isForInitializer(node: Node): node is ForInitializer;
export declare function isModuleBody(node: Node): node is ModuleBody;
/** @internal */
export declare function isNamespaceBody(node: Node): node is NamespaceBody;
/** @internal */
export declare function isJSDocNamespaceBody(node: Node): node is JSDocNamespaceBody;
export declare function isNamedImportBindings(node: Node): node is NamedImportBindings;
/** @internal */
export declare function isModuleOrEnumDeclaration(node: Node): node is ModuleDeclaration | EnumDeclaration;
/** @internal */
export declare function canHaveSymbol(node: Node): node is Declaration;
/** @internal */
export declare function canHaveLocals(node: Node): node is HasLocals;
/** @internal */
export declare function isDeclaration(node: Node): node is NamedDeclaration;
/** @internal */
export declare function isDeclarationStatement(node: Node): node is DeclarationStatement;
/**
 * Determines whether the node is a statement that is not also a declaration
 *
 * @internal
 */
export declare function isStatementButNotDeclaration(node: Node): node is Statement;
export declare function isStatement(node: Node): node is Statement;
/**
 * NOTE: This is similar to `isStatement` but does not access parent pointers.
 *
 * @internal
 */
export declare function isStatementOrBlock(node: Node): node is Statement | Block;
export declare function isModuleReference(node: Node): node is ModuleReference;
export declare function isJsxTagNameExpression(node: Node): node is JsxTagNameExpression;
export declare function isJsxChild(node: Node): node is JsxChild;
export declare function isJsxAttributeLike(node: Node): node is JsxAttributeLike;
export declare function isStringLiteralOrJsxExpression(node: Node): node is StringLiteral | JsxExpression;
export declare function isJsxOpeningLikeElement(node: Node): node is JsxOpeningLikeElement;
export declare function isCaseOrDefaultClause(node: Node): node is CaseOrDefaultClause;
/**
 * True if node is of some JSDoc syntax kind.
 *
 * @internal
 */
export declare function isJSDocNode(node: Node): boolean;
/** True if node is of a kind that may contain comment text. */
export declare function isJSDocCommentContainingNode(node: Node): boolean;
/** @internal */
export declare function isJSDocTag(node: Node): node is JSDocTag;
export declare function isSetAccessor(node: Node): node is SetAccessorDeclaration;
export declare function isGetAccessor(node: Node): node is GetAccessorDeclaration;
/**
 * True if has jsdoc nodes attached to it.
 *
 * @internal
 */
export declare function hasJSDocNodes(node: Node): node is HasJSDoc;
/**
 * True if has type node attached to it.
 *
 * @internal
 */
export declare function hasType(node: Node): node is HasType;
/**
 * True if has initializer node attached to it.
 *
 * @internal
 */
export declare function hasInitializer(node: Node): node is HasInitializer;
/** True if has initializer node attached to it. */
export declare function hasOnlyExpressionInitializer(node: Node): node is HasExpressionInitializer;
export declare function isObjectLiteralElement(node: Node): node is ObjectLiteralElement;
/** @internal */
export declare function isTypeReferenceType(node: Node): node is TypeReferenceType;
/** @internal */
export declare function guessIndentation(lines: string[]): number | undefined;
export declare function isStringLiteralLike(node: Node | FileReference): node is StringLiteralLike;
export declare function isJSDocLinkLike(node: Node): node is JSDocLink | JSDocLinkCode | JSDocLinkPlain;
export declare function hasRestParameter(s: SignatureDeclaration | JSDocSignature): boolean;
export declare function isRestParameter(node: ParameterDeclaration | JSDocParameterTag): boolean;
//# sourceMappingURL=utilitiesPublic.d.ts.map