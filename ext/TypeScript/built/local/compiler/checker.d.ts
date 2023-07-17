import { ModuleDeclaration, Node, Signature, Symbol, SymbolId, TypeChecker, TypeCheckerHost } from "./_namespaces/ts";
/** @internal */
export declare const enum TypeFacts {
    None = 0,
    TypeofEQString = 1,
    TypeofEQNumber = 2,
    TypeofEQBigInt = 4,
    TypeofEQBoolean = 8,
    TypeofEQSymbol = 16,
    TypeofEQObject = 32,
    TypeofEQFunction = 64,
    TypeofEQHostObject = 128,
    TypeofNEString = 256,
    TypeofNENumber = 512,
    TypeofNEBigInt = 1024,
    TypeofNEBoolean = 2048,
    TypeofNESymbol = 4096,
    TypeofNEObject = 8192,
    TypeofNEFunction = 16384,
    TypeofNEHostObject = 32768,
    EQUndefined = 65536,
    EQNull = 131072,
    EQUndefinedOrNull = 262144,
    NEUndefined = 524288,
    NENull = 1048576,
    NEUndefinedOrNull = 2097152,
    Truthy = 4194304,
    Falsy = 8388608,
    IsUndefined = 16777216,
    IsNull = 33554432,
    IsUndefinedOrNull = 50331648,
    All = 134217727,
    BaseStringStrictFacts = 3735041,
    BaseStringFacts = 12582401,
    StringStrictFacts = 16317953,
    StringFacts = 16776705,
    EmptyStringStrictFacts = 12123649,
    EmptyStringFacts = 12582401,
    NonEmptyStringStrictFacts = 7929345,
    NonEmptyStringFacts = 16776705,
    BaseNumberStrictFacts = 3734786,
    BaseNumberFacts = 12582146,
    NumberStrictFacts = 16317698,
    NumberFacts = 16776450,
    ZeroNumberStrictFacts = 12123394,
    ZeroNumberFacts = 12582146,
    NonZeroNumberStrictFacts = 7929090,
    NonZeroNumberFacts = 16776450,
    BaseBigIntStrictFacts = 3734276,
    BaseBigIntFacts = 12581636,
    BigIntStrictFacts = 16317188,
    BigIntFacts = 16775940,
    ZeroBigIntStrictFacts = 12122884,
    ZeroBigIntFacts = 12581636,
    NonZeroBigIntStrictFacts = 7928580,
    NonZeroBigIntFacts = 16775940,
    BaseBooleanStrictFacts = 3733256,
    BaseBooleanFacts = 12580616,
    BooleanStrictFacts = 16316168,
    BooleanFacts = 16774920,
    FalseStrictFacts = 12121864,
    FalseFacts = 12580616,
    TrueStrictFacts = 7927560,
    TrueFacts = 16774920,
    SymbolStrictFacts = 7925520,
    SymbolFacts = 16772880,
    ObjectStrictFacts = 7888800,
    ObjectFacts = 16736160,
    FunctionStrictFacts = 7880640,
    FunctionFacts = 16728000,
    VoidFacts = 9830144,
    UndefinedFacts = 26607360,
    NullFacts = 42917664,
    EmptyObjectStrictFacts = 83427327,
    EmptyObjectFacts = 83886079,
    UnknownFacts = 83886079,
    AllTypeofNE = 556800,
    OrFactsMask = 8256,
    AndFactsMask = 134209471
}
/** @internal */
export declare const enum CheckMode {
    Normal = 0,
    Contextual = 1,
    Inferential = 2,
    SkipContextSensitive = 4,
    SkipGenericFunctions = 8,
    IsForSignatureHelp = 16,
    IsForStringLiteralArgumentCompletions = 32,
    RestBindingElement = 64
}
/** @internal */
export declare const enum SignatureCheckMode {
    None = 0,
    BivariantCallback = 1,
    StrictCallback = 2,
    IgnoreReturnTypes = 4,
    StrictArity = 8,
    StrictTopSignature = 16,
    Callback = 3
}
/** @internal */
export declare function getNodeId(node: Node): number;
/** @internal */
export declare function getSymbolId(symbol: Symbol): SymbolId;
/** @internal */
export declare function isInstantiatedModule(node: ModuleDeclaration, preserveConstEnums: boolean): boolean;
/** @internal */
export declare function createTypeChecker(host: TypeCheckerHost): TypeChecker;
/** @internal */
export declare function signatureHasRestParameter(s: Signature): boolean;
/** @internal */
export declare function signatureHasLiteralTypes(s: Signature): boolean;
//# sourceMappingURL=checker.d.ts.map