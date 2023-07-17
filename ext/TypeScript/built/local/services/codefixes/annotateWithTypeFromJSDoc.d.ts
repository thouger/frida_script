import { FunctionLikeDeclaration, Node, PropertyDeclaration, PropertySignature, VariableDeclaration } from "../_namespaces/ts";
/** @internal */
export type DeclarationWithType = FunctionLikeDeclaration | VariableDeclaration | PropertySignature | PropertyDeclaration;
/** @internal */
export declare function parameterShouldGetTypeFromJSDoc(node: Node): node is DeclarationWithType;
//# sourceMappingURL=annotateWithTypeFromJSDoc.d.ts.map