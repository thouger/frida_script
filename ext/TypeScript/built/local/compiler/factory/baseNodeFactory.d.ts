import { Node, SyntaxKind } from "../_namespaces/ts";
/**
 * A `BaseNodeFactory` is an abstraction over an `ObjectAllocator` that handles caching `Node` constructors
 * and allocating `Node` instances based on a set of predefined types.
 *
 * @internal
 */
export interface BaseNodeFactory {
    createBaseSourceFileNode(kind: SyntaxKind.SourceFile): Node;
    createBaseIdentifierNode(kind: SyntaxKind.Identifier): Node;
    createBasePrivateIdentifierNode(kind: SyntaxKind.PrivateIdentifier): Node;
    createBaseTokenNode(kind: SyntaxKind): Node;
    createBaseNode(kind: SyntaxKind): Node;
}
/**
 * Creates a `BaseNodeFactory` which can be used to create `Node` instances from the constructors provided by the object allocator.
 *
 * @internal
 */
export declare function createBaseNodeFactory(): BaseNodeFactory;
//# sourceMappingURL=baseNodeFactory.d.ts.map