import { ArrowFunction, CallHierarchyIncomingCall, CallHierarchyItem, CallHierarchyOutgoingCall, CancellationToken, ClassDeclaration, ClassExpression, ClassStaticBlockDeclaration, FunctionDeclaration, FunctionExpression, GetAccessorDeclaration, Identifier, MethodDeclaration, ModuleDeclaration, Node, Program, SetAccessorDeclaration, SourceFile, VariableDeclaration } from "./_namespaces/ts";
/** @internal */
export type NamedExpression = ClassExpression & {
    name: Identifier;
} | FunctionExpression & {
    name: Identifier;
};
/** @internal */
export type ConstNamedExpression = ClassExpression & {
    name: undefined;
    parent: VariableDeclaration & {
        name: Identifier;
    };
} | FunctionExpression & {
    name: undefined;
    parent: VariableDeclaration & {
        name: Identifier;
    };
} | ArrowFunction & {
    name: undefined;
    parent: VariableDeclaration & {
        name: Identifier;
    };
};
/** @internal */
export type CallHierarchyDeclaration = SourceFile | ModuleDeclaration & {
    name: Identifier;
} | FunctionDeclaration | ClassDeclaration | ClassStaticBlockDeclaration | MethodDeclaration | GetAccessorDeclaration | SetAccessorDeclaration | NamedExpression | ConstNamedExpression;
/**
 * Resolves the call hierarchy declaration for a node.
 *
 * @internal
 */
export declare function resolveCallHierarchyDeclaration(program: Program, location: Node): CallHierarchyDeclaration | CallHierarchyDeclaration[] | undefined;
/**
 * Creates a `CallHierarchyItem` for a call hierarchy declaration.
 *
 * @internal
 */
export declare function createCallHierarchyItem(program: Program, node: CallHierarchyDeclaration): CallHierarchyItem;
/**
 * Gets the call sites that call into the provided call hierarchy declaration.
 *
 * @internal
 */
export declare function getIncomingCalls(program: Program, declaration: CallHierarchyDeclaration, cancellationToken: CancellationToken): CallHierarchyIncomingCall[];
/**
 * Gets the call sites that call out of the provided call hierarchy declaration.
 *
 * @internal
 */
export declare function getOutgoingCalls(program: Program, declaration: CallHierarchyDeclaration): CallHierarchyOutgoingCall[];
//# sourceMappingURL=callHierarchy.d.ts.map