import { SyntaxKind } from "../_namespaces/ts";
import { FormattingContext } from "../_namespaces/ts.formatting";
/** @internal */
export interface Rule {
    readonly debugName: string;
    readonly context: readonly ContextPredicate[];
    readonly action: RuleAction;
    readonly flags: RuleFlags;
}
/** @internal */
export type ContextPredicate = (context: FormattingContext) => boolean;
/** @internal */
export declare const anyContext: readonly ContextPredicate[];
/** @internal */
export declare const enum RuleAction {
    None = 0,
    StopProcessingSpaceActions = 1,
    StopProcessingTokenActions = 2,
    InsertSpace = 4,
    InsertNewLine = 8,
    DeleteSpace = 16,
    DeleteToken = 32,
    InsertTrailingSemicolon = 64,
    StopAction = 3,
    ModifySpaceAction = 28,
    ModifyTokenAction = 96
}
/** @internal */
export declare const enum RuleFlags {
    None = 0,
    CanDeleteNewLines = 1
}
/** @internal */
export interface TokenRange {
    readonly tokens: readonly SyntaxKind[];
    readonly isSpecific: boolean;
}
//# sourceMappingURL=rule.d.ts.map