import { __String, Bundle, EmitResolver, FunctionLikeDeclaration, NodeFactory, SourceFile, TransformationContext, VariableStatement } from "../_namespaces/ts";
/** @internal */
export declare function transformES2017(context: TransformationContext): (x: SourceFile | Bundle) => SourceFile | Bundle;
/**
 * Creates a variable named `_super` with accessor properties for the given property names.
 *
 * @internal
 */
export declare function createSuperAccessVariableStatement(factory: NodeFactory, resolver: EmitResolver, node: FunctionLikeDeclaration, names: Set<__String>): VariableStatement;
//# sourceMappingURL=es2017.d.ts.map