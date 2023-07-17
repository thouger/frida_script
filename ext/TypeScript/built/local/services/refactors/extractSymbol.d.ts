import { ApplicableRefactorInfo, Diagnostic, DiagnosticMessage, Expression, Node, RefactorContext, RefactorEditInfo, SourceFile, Statement, TextSpan } from "../_namespaces/ts";
/**
 * Compute the associated code actions
 * Exported for tests.
 *
 * @internal
 */
export declare function getRefactorActionsToExtractSymbol(context: RefactorContext): readonly ApplicableRefactorInfo[];
/**
 * Exported for tests
 *
 * @internal
 */
export declare function getRefactorEditsToExtractSymbol(context: RefactorContext, actionName: string): RefactorEditInfo | undefined;
/** @internal */
export declare namespace Messages {
    const cannotExtractRange: DiagnosticMessage;
    const cannotExtractImport: DiagnosticMessage;
    const cannotExtractSuper: DiagnosticMessage;
    const cannotExtractJSDoc: DiagnosticMessage;
    const cannotExtractEmpty: DiagnosticMessage;
    const expressionExpected: DiagnosticMessage;
    const uselessConstantType: DiagnosticMessage;
    const statementOrExpressionExpected: DiagnosticMessage;
    const cannotExtractRangeContainingConditionalBreakOrContinueStatements: DiagnosticMessage;
    const cannotExtractRangeContainingConditionalReturnStatement: DiagnosticMessage;
    const cannotExtractRangeContainingLabeledBreakOrContinueStatementWithTargetOutsideOfTheRange: DiagnosticMessage;
    const cannotExtractRangeThatContainsWritesToReferencesLocatedOutsideOfTheTargetRangeInGenerators: DiagnosticMessage;
    const typeWillNotBeVisibleInTheNewScope: DiagnosticMessage;
    const functionWillNotBeVisibleInTheNewScope: DiagnosticMessage;
    const cannotExtractIdentifier: DiagnosticMessage;
    const cannotExtractExportedEntity: DiagnosticMessage;
    const cannotWriteInExpression: DiagnosticMessage;
    const cannotExtractReadonlyPropertyInitializerOutsideConstructor: DiagnosticMessage;
    const cannotExtractAmbientBlock: DiagnosticMessage;
    const cannotAccessVariablesFromNestedScopes: DiagnosticMessage;
    const cannotExtractToJSClass: DiagnosticMessage;
    const cannotExtractToExpressionArrowFunction: DiagnosticMessage;
    const cannotExtractFunctionsContainingThisToMethod: DiagnosticMessage;
}
/** @internal */
export declare enum RangeFacts {
    None = 0,
    HasReturn = 1,
    IsGenerator = 2,
    IsAsyncFunction = 4,
    UsesThis = 8,
    UsesThisInFunction = 16,
    /**
     * The range is in a function which needs the 'static' modifier in a class
     */
    InStaticRegion = 32
}
/**
 * Represents an expression or a list of statements that should be extracted with some extra information
 *
 * @internal
 */
export interface TargetRange {
    readonly range: Expression | Statement[];
    readonly facts: RangeFacts;
    /**
     * If `this` is referring to a function instead of class, we need to retrieve its type.
     */
    readonly thisNode: Node | undefined;
}
/**
 * Result of 'getRangeToExtract' operation: contains either a range or a list of errors
 *
 * @internal
 */
export type RangeToExtract = {
    readonly targetRange?: never;
    readonly errors: readonly Diagnostic[];
} | {
    readonly targetRange: TargetRange;
    readonly errors?: never;
};
/**
 * getRangeToExtract takes a span inside a text file and returns either an expression or an array
 * of statements representing the minimum set of nodes needed to extract the entire span. This
 * process may fail, in which case a set of errors is returned instead. These errors are shown to
 * users if they have the provideRefactorNotApplicableReason option set.
 *
 * @internal
 */
export declare function getRangeToExtract(sourceFile: SourceFile, span: TextSpan, invoked?: boolean): RangeToExtract;
//# sourceMappingURL=extractSymbol.d.ts.map