import { CallLikeExpression, CancellationToken, Node, Program, SignatureHelpItems, SignatureHelpTriggerReason, SourceFile } from "./_namespaces/ts";
/** @internal */
export declare function getSignatureHelpItems(program: Program, sourceFile: SourceFile, position: number, triggerReason: SignatureHelpTriggerReason | undefined, cancellationToken: CancellationToken): SignatureHelpItems | undefined;
/** @internal */
export interface ArgumentInfoForCompletions {
    readonly invocation: CallLikeExpression;
    readonly argumentIndex: number;
    readonly argumentCount: number;
}
/** @internal */
export declare function getArgumentInfoForCompletions(node: Node, position: number, sourceFile: SourceFile): ArgumentInfoForCompletions | undefined;
//# sourceMappingURL=signatureHelp.d.ts.map