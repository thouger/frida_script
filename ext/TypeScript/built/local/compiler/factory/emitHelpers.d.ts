import { __String, ArrayLiteralExpression, BindingOrAssignmentElement, Block, Comparison, EmitHelper, EmitHelperUniqueNameCallback, EntityName, Expression, FunctionExpression, Identifier, PrivateIdentifier, TextRange, TransformationContext, UnscopedEmitHelper } from "../_namespaces/ts";
/** @internal */
export declare const enum PrivateIdentifierKind {
    Field = "f",
    Method = "m",
    Accessor = "a"
}
/**
 * Describes the decorator context object passed to a native ECMAScript decorator for a class.
 *
 * @internal
 */
export interface ESDecorateClassContext {
    /**
     * The kind of the decorated element.
     */
    kind: "class";
    /**
     * The name of the decorated element.
     */
    name: Expression;
}
/**
 * Describes the decorator context object passed to a native ECMAScript decorator for a class element.
 *
 * @internal
 */
export interface ESDecorateClassElementContext {
    /**
     * The kind of the decorated element.
     */
    kind: "method" | "getter" | "setter" | "accessor" | "field";
    name: ESDecorateName;
    static: boolean;
    private: boolean;
    access: ESDecorateClassElementAccess;
}
/** @internal */
export interface ESDecorateClassElementAccess {
    get?: boolean;
    set?: boolean;
}
/** @internal */
export type ESDecorateName = {
    computed: true;
    name: Expression;
} | {
    computed: false;
    name: Identifier | PrivateIdentifier;
};
/** @internal */
export type ESDecorateContext = ESDecorateClassContext | ESDecorateClassElementContext;
/** @internal */
export interface EmitHelperFactory {
    getUnscopedHelperName(name: string): Identifier;
    createDecorateHelper(decoratorExpressions: readonly Expression[], target: Expression, memberName?: Expression, descriptor?: Expression): Expression;
    createMetadataHelper(metadataKey: string, metadataValue: Expression): Expression;
    createParamHelper(expression: Expression, parameterOffset: number): Expression;
    createESDecorateHelper(ctor: Expression, descriptorIn: Expression, decorators: Expression, contextIn: ESDecorateContext, initializers: Expression, extraInitializers: Expression): Expression;
    createRunInitializersHelper(thisArg: Expression, initializers: Expression, value?: Expression): Expression;
    createAssignHelper(attributesSegments: readonly Expression[]): Expression;
    createAwaitHelper(expression: Expression): Expression;
    createAsyncGeneratorHelper(generatorFunc: FunctionExpression, hasLexicalThis: boolean): Expression;
    createAsyncDelegatorHelper(expression: Expression): Expression;
    createAsyncValuesHelper(expression: Expression): Expression;
    createRestHelper(value: Expression, elements: readonly BindingOrAssignmentElement[], computedTempVariables: readonly Expression[] | undefined, location: TextRange): Expression;
    createAwaiterHelper(hasLexicalThis: boolean, hasLexicalArguments: boolean, promiseConstructor: EntityName | Expression | undefined, body: Block): Expression;
    createExtendsHelper(name: Identifier): Expression;
    createTemplateObjectHelper(cooked: ArrayLiteralExpression, raw: ArrayLiteralExpression): Expression;
    createSpreadArrayHelper(to: Expression, from: Expression, packFrom: boolean): Expression;
    createPropKeyHelper(expr: Expression): Expression;
    createSetFunctionNameHelper(f: Expression, name: Expression, prefix?: string): Expression;
    createValuesHelper(expression: Expression): Expression;
    createReadHelper(iteratorRecord: Expression, count: number | undefined): Expression;
    createGeneratorHelper(body: FunctionExpression): Expression;
    createCreateBindingHelper(module: Expression, inputName: Expression, outputName: Expression | undefined): Expression;
    createImportStarHelper(expression: Expression): Expression;
    createImportStarCallbackHelper(): Expression;
    createImportDefaultHelper(expression: Expression): Expression;
    createExportStarHelper(moduleExpression: Expression, exportsExpression?: Expression): Expression;
    createClassPrivateFieldGetHelper(receiver: Expression, state: Identifier, kind: PrivateIdentifierKind, f: Identifier | undefined): Expression;
    createClassPrivateFieldSetHelper(receiver: Expression, state: Identifier, value: Expression, kind: PrivateIdentifierKind, f: Identifier | undefined): Expression;
    createClassPrivateFieldInHelper(state: Identifier, receiver: Expression): Expression;
}
/** @internal */
export declare function createEmitHelperFactory(context: TransformationContext): EmitHelperFactory;
/** @internal */
export declare function compareEmitHelpers(x: EmitHelper, y: EmitHelper): Comparison;
/**
 * @param input Template string input strings
 * @param args Names which need to be made file-level unique
 *
 * @internal
 */
export declare function helperString(input: TemplateStringsArray, ...args: string[]): (uniqueName: EmitHelperUniqueNameCallback) => string;
/** @internal */
export declare const decorateHelper: UnscopedEmitHelper;
/** @internal */
export declare const metadataHelper: UnscopedEmitHelper;
/** @internal */
export declare const paramHelper: UnscopedEmitHelper;
/** @internal */
export declare const esDecorateHelper: UnscopedEmitHelper;
/** @internal */
export declare const runInitializersHelper: UnscopedEmitHelper;
/** @internal */
export declare const assignHelper: UnscopedEmitHelper;
/** @internal */
export declare const awaitHelper: UnscopedEmitHelper;
/** @internal */
export declare const asyncGeneratorHelper: UnscopedEmitHelper;
/** @internal */
export declare const asyncDelegator: UnscopedEmitHelper;
/** @internal */
export declare const asyncValues: UnscopedEmitHelper;
/** @internal */
export declare const restHelper: UnscopedEmitHelper;
/** @internal */
export declare const awaiterHelper: UnscopedEmitHelper;
/** @internal */
export declare const extendsHelper: UnscopedEmitHelper;
/** @internal */
export declare const templateObjectHelper: UnscopedEmitHelper;
/** @internal */
export declare const readHelper: UnscopedEmitHelper;
/** @internal */
export declare const spreadArrayHelper: UnscopedEmitHelper;
/** @internal */
export declare const propKeyHelper: UnscopedEmitHelper;
/** @internal */
export declare const setFunctionNameHelper: UnscopedEmitHelper;
/** @internal */
export declare const valuesHelper: UnscopedEmitHelper;
/** @internal */
export declare const generatorHelper: UnscopedEmitHelper;
/** @internal */
export declare const createBindingHelper: UnscopedEmitHelper;
/** @internal */
export declare const setModuleDefaultHelper: UnscopedEmitHelper;
/** @internal */
export declare const importStarHelper: UnscopedEmitHelper;
/** @internal */
export declare const importDefaultHelper: UnscopedEmitHelper;
/** @internal */
export declare const exportStarHelper: UnscopedEmitHelper;
/**
 * Parameters:
 *  @param receiver — The object from which the private member will be read.
 *  @param state — One of the following:
 *      - A WeakMap used to read a private instance field.
 *      - A WeakSet used as an instance brand for private instance methods and accessors.
 *      - A function value that should be the undecorated class constructor used to brand check private static fields, methods, and accessors.
 *  @param kind — (optional pre TS 4.3, required for TS 4.3+) One of the following values:
 *      - undefined — Indicates a private instance field (pre TS 4.3).
 *      - "f" — Indicates a private field (instance or static).
 *      - "m" — Indicates a private method (instance or static).
 *      - "a" — Indicates a private accessor (instance or static).
 *  @param f — (optional pre TS 4.3) Depends on the arguments for state and kind:
 *      - If kind is "m", this should be the function corresponding to the static or instance method.
 *      - If kind is "a", this should be the function corresponding to the getter method, or undefined if the getter was not defined.
 *      - If kind is "f" and state is a function, this should be an object holding the value of a static field, or undefined if the static field declaration has not yet been evaluated.
 * Usage:
 * This helper will only ever be used by the compiler in the following ways:
 *
 * Reading from a private instance field (pre TS 4.3):
 *      __classPrivateFieldGet(<any>, <WeakMap>)
 *
 * Reading from a private instance field (TS 4.3+):
 *      __classPrivateFieldGet(<any>, <WeakMap>, "f")
 *
 * Reading from a private instance get accessor (when defined, TS 4.3+):
 *      __classPrivateFieldGet(<any>, <WeakSet>, "a", <function>)
 *
 * Reading from a private instance get accessor (when not defined, TS 4.3+):
 *      __classPrivateFieldGet(<any>, <WeakSet>, "a", void 0)
 *      NOTE: This always results in a runtime error.
 *
 * Reading from a private instance method (TS 4.3+):
 *      __classPrivateFieldGet(<any>, <WeakSet>, "m", <function>)
 *
 * Reading from a private static field (TS 4.3+):
 *      __classPrivateFieldGet(<any>, <constructor>, "f", <{ value: any }>)
 *
 * Reading from a private static get accessor (when defined, TS 4.3+):
 *      __classPrivateFieldGet(<any>, <constructor>, "a", <function>)
 *
 * Reading from a private static get accessor (when not defined, TS 4.3+):
 *      __classPrivateFieldGet(<any>, <constructor>, "a", void 0)
 *      NOTE: This always results in a runtime error.
 *
 * Reading from a private static method (TS 4.3+):
 *      __classPrivateFieldGet(<any>, <constructor>, "m", <function>)
 *
 * @internal
 */
export declare const classPrivateFieldGetHelper: UnscopedEmitHelper;
/**
 * Parameters:
 *  @param receiver — The object on which the private member will be set.
 *  @param state — One of the following:
 *      - A WeakMap used to store a private instance field.
 *      - A WeakSet used as an instance brand for private instance methods and accessors.
 *      - A function value that should be the undecorated class constructor used to brand check private static fields, methods, and accessors.
 *  @param value — The value to set.
 *  @param kind — (optional pre TS 4.3, required for TS 4.3+) One of the following values:
 *       - undefined — Indicates a private instance field (pre TS 4.3).
 *       - "f" — Indicates a private field (instance or static).
 *       - "m" — Indicates a private method (instance or static).
 *       - "a" — Indicates a private accessor (instance or static).
 *   @param f — (optional pre TS 4.3) Depends on the arguments for state and kind:
 *       - If kind is "m", this should be the function corresponding to the static or instance method.
 *       - If kind is "a", this should be the function corresponding to the setter method, or undefined if the setter was not defined.
 *       - If kind is "f" and state is a function, this should be an object holding the value of a static field, or undefined if the static field declaration has not yet been evaluated.
 * Usage:
 * This helper will only ever be used by the compiler in the following ways:
 *
 * Writing to a private instance field (pre TS 4.3):
 *      __classPrivateFieldSet(<any>, <WeakMap>, <any>)
 *
 * Writing to a private instance field (TS 4.3+):
 *      __classPrivateFieldSet(<any>, <WeakMap>, <any>, "f")
 *
 * Writing to a private instance set accessor (when defined, TS 4.3+):
 *      __classPrivateFieldSet(<any>, <WeakSet>, <any>, "a", <function>)
 *
 * Writing to a private instance set accessor (when not defined, TS 4.3+):
 *      __classPrivateFieldSet(<any>, <WeakSet>, <any>, "a", void 0)
 *      NOTE: This always results in a runtime error.
 *
 * Writing to a private instance method (TS 4.3+):
 *      __classPrivateFieldSet(<any>, <WeakSet>, <any>, "m", <function>)
 *      NOTE: This always results in a runtime error.
 *
 * Writing to a private static field (TS 4.3+):
 *      __classPrivateFieldSet(<any>, <constructor>, <any>, "f", <{ value: any }>)
 *
 * Writing to a private static set accessor (when defined, TS 4.3+):
 *      __classPrivateFieldSet(<any>, <constructor>, <any>, "a", <function>)
 *
 * Writing to a private static set accessor (when not defined, TS 4.3+):
 *      __classPrivateFieldSet(<any>, <constructor>, <any>, "a", void 0)
 *      NOTE: This always results in a runtime error.
 *
 * Writing to a private static method (TS 4.3+):
 *      __classPrivateFieldSet(<any>, <constructor>, <any>, "m", <function>)
 *      NOTE: This always results in a runtime error.
 *
 * @internal
 */
export declare const classPrivateFieldSetHelper: UnscopedEmitHelper;
/**
 * Parameters:
 *  @param state — One of the following:
 *      - A WeakMap when the member is a private instance field.
 *      - A WeakSet when the member is a private instance method or accessor.
 *      - A function value that should be the undecorated class constructor when the member is a private static field, method, or accessor.
 *  @param receiver — The object being checked if it has the private member.
 *
 * Usage:
 * This helper is used to transform `#field in expression` to
 *      `__classPrivateFieldIn(<weakMap/weakSet/constructor>, expression)`
 *
 * @internal
 */
export declare const classPrivateFieldInHelper: UnscopedEmitHelper;
/** @internal */
export declare function getAllUnscopedEmitHelpers(): ReadonlyMap<string, UnscopedEmitHelper>;
/** @internal */
export declare const asyncSuperHelper: EmitHelper;
/** @internal */
export declare const advancedAsyncSuperHelper: EmitHelper;
/** @internal */
export declare function isCallToHelper(firstSegment: Expression, helperName: __String): boolean;
//# sourceMappingURL=emitHelpers.d.ts.map