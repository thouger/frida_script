import { AccessExpression, AutoGenerateInfo, EmitFlags, EmitHelper, EmitNode, Identifier, ImportSpecifier, InternalEmitFlags, Node, NodeArray, PrivateIdentifier, SnippetElement, SourceFile, SourceMapRange, SyntaxKind, SynthesizedComment, TextRange, TypeNode, TypeParameterDeclaration } from "../_namespaces/ts";
/**
 * Associates a node with the current transformation, initializing
 * various transient transformation properties.
 * @internal
 */
export declare function getOrCreateEmitNode(node: Node): EmitNode;
/**
 * Clears any `EmitNode` entries from parse-tree nodes.
 * @param sourceFile A source file.
 */
export declare function disposeEmitNodes(sourceFile: SourceFile | undefined): void;
/**
 * Sets `EmitFlags.NoComments` on a node and removes any leading and trailing synthetic comments.
 * @internal
 */
export declare function removeAllComments<T extends Node>(node: T): T;
/**
 * Sets flags that control emit behavior of a node.
 */
export declare function setEmitFlags<T extends Node>(node: T, emitFlags: EmitFlags): T;
/**
 * Sets flags that control emit behavior of a node.
 *
 * @internal
 */
export declare function addEmitFlags<T extends Node>(node: T, emitFlags: EmitFlags): T;
/**
 * Sets flags that control emit behavior of a node.
 *
 * @internal
 */
export declare function setInternalEmitFlags<T extends Node>(node: T, emitFlags: InternalEmitFlags): T;
/**
 * Sets flags that control emit behavior of a node.
 *
 * @internal
 */
export declare function addInternalEmitFlags<T extends Node>(node: T, emitFlags: InternalEmitFlags): T;
/**
 * Gets a custom text range to use when emitting source maps.
 */
export declare function getSourceMapRange(node: Node): SourceMapRange;
/**
 * Sets a custom text range to use when emitting source maps.
 */
export declare function setSourceMapRange<T extends Node>(node: T, range: SourceMapRange | undefined): T;
/**
 * Gets the TextRange to use for source maps for a token of a node.
 */
export declare function getTokenSourceMapRange(node: Node, token: SyntaxKind): SourceMapRange | undefined;
/**
 * Sets the TextRange to use for source maps for a token of a node.
 */
export declare function setTokenSourceMapRange<T extends Node>(node: T, token: SyntaxKind, range: SourceMapRange | undefined): T;
/**
 * Gets a custom text range to use when emitting comments.
 *
 * @internal
 */
export declare function getStartsOnNewLine(node: Node): boolean | undefined;
/**
 * Sets a custom text range to use when emitting comments.
 *
 * @internal
 */
export declare function setStartsOnNewLine<T extends Node>(node: T, newLine: boolean): T;
/**
 * Gets a custom text range to use when emitting comments.
 */
export declare function getCommentRange(node: Node): TextRange;
/**
 * Sets a custom text range to use when emitting comments.
 */
export declare function setCommentRange<T extends Node>(node: T, range: TextRange): T;
export declare function getSyntheticLeadingComments(node: Node): SynthesizedComment[] | undefined;
export declare function setSyntheticLeadingComments<T extends Node>(node: T, comments: SynthesizedComment[] | undefined): T;
export declare function addSyntheticLeadingComment<T extends Node>(node: T, kind: SyntaxKind.SingleLineCommentTrivia | SyntaxKind.MultiLineCommentTrivia, text: string, hasTrailingNewLine?: boolean): T;
export declare function getSyntheticTrailingComments(node: Node): SynthesizedComment[] | undefined;
export declare function setSyntheticTrailingComments<T extends Node>(node: T, comments: SynthesizedComment[] | undefined): T;
export declare function addSyntheticTrailingComment<T extends Node>(node: T, kind: SyntaxKind.SingleLineCommentTrivia | SyntaxKind.MultiLineCommentTrivia, text: string, hasTrailingNewLine?: boolean): T;
export declare function moveSyntheticComments<T extends Node>(node: T, original: Node): T;
/**
 * Gets the constant value to emit for an expression representing an enum.
 */
export declare function getConstantValue(node: AccessExpression): string | number | undefined;
/**
 * Sets the constant value to emit for an expression.
 */
export declare function setConstantValue(node: AccessExpression, value: string | number): AccessExpression;
/**
 * Adds an EmitHelper to a node.
 */
export declare function addEmitHelper<T extends Node>(node: T, helper: EmitHelper): T;
/**
 * Add EmitHelpers to a node.
 */
export declare function addEmitHelpers<T extends Node>(node: T, helpers: EmitHelper[] | undefined): T;
/**
 * Removes an EmitHelper from a node.
 */
export declare function removeEmitHelper(node: Node, helper: EmitHelper): boolean;
/**
 * Gets the EmitHelpers of a node.
 */
export declare function getEmitHelpers(node: Node): EmitHelper[] | undefined;
/**
 * Moves matching emit helpers from a source node to a target node.
 */
export declare function moveEmitHelpers(source: Node, target: Node, predicate: (helper: EmitHelper) => boolean): void;
/**
 * Gets the SnippetElement of a node.
 *
 * @internal
 */
export declare function getSnippetElement(node: Node): SnippetElement | undefined;
/**
 * Sets the SnippetElement of a node.
 *
 * @internal
 */
export declare function setSnippetElement<T extends Node>(node: T, snippet: SnippetElement): T;
/** @internal */
export declare function ignoreSourceNewlines<T extends Node>(node: T): T;
/** @internal */
export declare function setTypeNode<T extends Node>(node: T, type: TypeNode): T;
/** @internal */
export declare function getTypeNode<T extends Node>(node: T): TypeNode | undefined;
/** @internal */
export declare function setIdentifierTypeArguments<T extends Identifier>(node: T, typeArguments: NodeArray<TypeNode | TypeParameterDeclaration> | undefined): T;
/** @internal */
export declare function getIdentifierTypeArguments(node: Identifier): NodeArray<TypeNode | TypeParameterDeclaration> | undefined;
/** @internal */
export declare function setIdentifierAutoGenerate<T extends Identifier | PrivateIdentifier>(node: T, autoGenerate: AutoGenerateInfo | undefined): T;
/** @internal */
export declare function getIdentifierAutoGenerate(node: Identifier | PrivateIdentifier): AutoGenerateInfo | undefined;
/** @internal */
export declare function setIdentifierGeneratedImportReference<T extends Identifier | PrivateIdentifier>(node: T, value: ImportSpecifier | undefined): T;
/** @internal */
export declare function getIdentifierGeneratedImportReference(node: Identifier | PrivateIdentifier): ImportSpecifier | undefined;
//# sourceMappingURL=emitNode.d.ts.map