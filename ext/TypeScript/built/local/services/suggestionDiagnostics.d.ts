import { ArrowFunction, CallExpression, CancellationToken, DiagnosticWithLocation, FunctionDeclaration, FunctionExpression, FunctionLikeDeclaration, MethodDeclaration, Node, Program, ReturnStatement, SourceFile, TypeChecker } from "./_namespaces/ts";
/** @internal */
export declare function computeSuggestionDiagnostics(sourceFile: SourceFile, program: Program, cancellationToken: CancellationToken): DiagnosticWithLocation[];
/** @internal */
export declare function returnsPromise(node: FunctionLikeDeclaration, checker: TypeChecker): boolean;
/** @internal */
export declare function isReturnStatementWithFixablePromiseHandler(node: Node, checker: TypeChecker): node is ReturnStatement & {
    expression: CallExpression;
};
/** @internal */
export declare function isFixablePromiseHandler(node: Node, checker: TypeChecker): boolean;
/** @internal */
export declare function canBeConvertedToAsync(node: Node): node is FunctionDeclaration | MethodDeclaration | FunctionExpression | ArrowFunction;
//# sourceMappingURL=suggestionDiagnostics.d.ts.map