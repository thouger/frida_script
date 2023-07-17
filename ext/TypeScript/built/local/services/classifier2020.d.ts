import { CancellationToken, Classifications, ClassifiedSpan2020, Program, SourceFile, TextSpan } from "./_namespaces/ts";
/** @internal */
export declare const enum TokenEncodingConsts {
    typeOffset = 8,
    modifierMask = 255
}
/** @internal */
export declare const enum TokenType {
    class = 0,
    enum = 1,
    interface = 2,
    namespace = 3,
    typeParameter = 4,
    type = 5,
    parameter = 6,
    variable = 7,
    enumMember = 8,
    property = 9,
    function = 10,
    member = 11
}
/** @internal */
export declare const enum TokenModifier {
    declaration = 0,
    static = 1,
    async = 2,
    readonly = 3,
    defaultLibrary = 4,
    local = 5
}
/**
 * This is mainly used internally for testing
 *
 * @internal
 */
export declare function getSemanticClassifications(program: Program, cancellationToken: CancellationToken, sourceFile: SourceFile, span: TextSpan): ClassifiedSpan2020[];
/** @internal */
export declare function getEncodedSemanticClassifications(program: Program, cancellationToken: CancellationToken, sourceFile: SourceFile, span: TextSpan): Classifications;
//# sourceMappingURL=classifier2020.d.ts.map