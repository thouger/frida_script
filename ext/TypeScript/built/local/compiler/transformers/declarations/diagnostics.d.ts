import { BinaryExpression, BindingElement, CallSignatureDeclaration, ConstructorDeclaration, ConstructSignatureDeclaration, DeclarationName, DiagnosticMessage, ElementAccessExpression, ExpressionWithTypeArguments, FunctionDeclaration, GetAccessorDeclaration, ImportEqualsDeclaration, IndexSignatureDeclaration, JSDocCallbackTag, JSDocEnumTag, JSDocTypedefTag, MethodDeclaration, MethodSignature, Node, ParameterDeclaration, PropertyAccessExpression, PropertyDeclaration, PropertySignature, QualifiedName, SetAccessorDeclaration, SymbolAccessibilityResult, TypeAliasDeclaration, TypeParameterDeclaration, VariableDeclaration } from "../../_namespaces/ts";
/** @internal */
export type GetSymbolAccessibilityDiagnostic = (symbolAccessibilityResult: SymbolAccessibilityResult) => (SymbolAccessibilityDiagnostic | undefined);
/** @internal */
export interface SymbolAccessibilityDiagnostic {
    errorNode: Node;
    diagnosticMessage: DiagnosticMessage;
    typeName?: DeclarationName | QualifiedName;
}
/** @internal */
export type DeclarationDiagnosticProducing = VariableDeclaration | PropertyDeclaration | PropertySignature | BindingElement | SetAccessorDeclaration | GetAccessorDeclaration | ConstructSignatureDeclaration | CallSignatureDeclaration | MethodDeclaration | MethodSignature | FunctionDeclaration | ParameterDeclaration | TypeParameterDeclaration | ExpressionWithTypeArguments | ImportEqualsDeclaration | TypeAliasDeclaration | ConstructorDeclaration | IndexSignatureDeclaration | PropertyAccessExpression | ElementAccessExpression | BinaryExpression | JSDocTypedefTag | JSDocCallbackTag | JSDocEnumTag;
/** @internal */
export declare function canProduceDiagnostics(node: Node): node is DeclarationDiagnosticProducing;
/** @internal */
export declare function createGetSymbolAccessibilityDiagnosticForNodeName(node: DeclarationDiagnosticProducing): (symbolAccessibilityResult: SymbolAccessibilityResult) => SymbolAccessibilityDiagnostic | undefined;
/** @internal */
export declare function createGetSymbolAccessibilityDiagnosticForNode(node: DeclarationDiagnosticProducing): GetSymbolAccessibilityDiagnostic;
//# sourceMappingURL=diagnostics.d.ts.map