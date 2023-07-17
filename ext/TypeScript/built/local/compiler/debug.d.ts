import * as ts from "./_namespaces/ts";
import { AnyFunction, AssertionLevel, CheckMode, EmitFlags, FlowFlags, FlowNode, FlowNodeBase, ModifierFlags, Node, NodeArray, NodeFlags, ObjectFlags, RelationComparisonResult, SignatureCheckMode, SignatureFlags, SnippetKind, Symbol, SymbolFlags, SyntaxKind, TransformFlags, Type, TypeFacts, TypeFlags, TypeMapKind, TypeMapper, VarianceFlags } from "./_namespaces/ts";
/** @internal */
export declare enum LogLevel {
    Off = 0,
    Error = 1,
    Warning = 2,
    Info = 3,
    Verbose = 4
}
/** @internal */
export interface LoggingHost {
    log(level: LogLevel, s: string): void;
}
/** @internal */
export declare namespace Debug {
    let currentLogLevel: ts.LogLevel;
    let isDebugging: boolean;
    let loggingHost: LoggingHost | undefined;
    function shouldLog(level: LogLevel): boolean;
    function log(s: string): void;
    namespace log {
        function error(s: string): void;
        function warn(s: string): void;
        function log(s: string): void;
        function trace(s: string): void;
    }
    function getAssertionLevel(): ts.AssertionLevel;
    function setAssertionLevel(level: AssertionLevel): void;
    function shouldAssert(level: AssertionLevel): boolean;
    function fail(message?: string, stackCrawlMark?: AnyFunction): never;
    function failBadSyntaxKind(node: Node, message?: string, stackCrawlMark?: AnyFunction): never;
    function assert(expression: unknown, message?: string, verboseDebugInfo?: string | (() => string), stackCrawlMark?: AnyFunction): asserts expression;
    function assertEqual<T>(a: T, b: T, msg?: string, msg2?: string, stackCrawlMark?: AnyFunction): void;
    function assertLessThan(a: number, b: number, msg?: string, stackCrawlMark?: AnyFunction): void;
    function assertLessThanOrEqual(a: number, b: number, stackCrawlMark?: AnyFunction): void;
    function assertGreaterThanOrEqual(a: number, b: number, stackCrawlMark?: AnyFunction): void;
    function assertIsDefined<T>(value: T, message?: string, stackCrawlMark?: AnyFunction): asserts value is NonNullable<T>;
    function checkDefined<T>(value: T | null | undefined, message?: string, stackCrawlMark?: AnyFunction): T;
    function assertEachIsDefined<T extends Node>(value: NodeArray<T>, message?: string, stackCrawlMark?: AnyFunction): asserts value is NodeArray<T>;
    function assertEachIsDefined<T>(value: readonly T[], message?: string, stackCrawlMark?: AnyFunction): asserts value is readonly NonNullable<T>[];
    function checkEachDefined<T, A extends readonly T[]>(value: A, message?: string, stackCrawlMark?: AnyFunction): A;
    function assertNever(member: never, message?: string, stackCrawlMark?: AnyFunction): never;
    function assertEachNode<T extends Node, U extends T>(nodes: NodeArray<T>, test: (node: T) => node is U, message?: string, stackCrawlMark?: AnyFunction): asserts nodes is NodeArray<U>;
    function assertEachNode<T extends Node, U extends T>(nodes: readonly T[], test: (node: T) => node is U, message?: string, stackCrawlMark?: AnyFunction): asserts nodes is readonly U[];
    function assertEachNode<T extends Node, U extends T>(nodes: NodeArray<T> | undefined, test: (node: T) => node is U, message?: string, stackCrawlMark?: AnyFunction): asserts nodes is NodeArray<U> | undefined;
    function assertEachNode<T extends Node, U extends T>(nodes: readonly T[] | undefined, test: (node: T) => node is U, message?: string, stackCrawlMark?: AnyFunction): asserts nodes is readonly U[] | undefined;
    function assertEachNode(nodes: readonly Node[], test: ((node: Node) => boolean) | undefined, message?: string, stackCrawlMark?: AnyFunction): void;
    function assertNode<T extends Node, U extends T>(node: T | undefined, test: (node: T) => node is U, message?: string, stackCrawlMark?: AnyFunction): asserts node is U;
    function assertNode(node: Node | undefined, test: ((node: Node) => boolean) | undefined, message?: string, stackCrawlMark?: AnyFunction): void;
    function assertNotNode<T extends Node, U extends T>(node: T | undefined, test: (node: Node) => node is U, message?: string, stackCrawlMark?: AnyFunction): asserts node is Exclude<T, U>;
    function assertNotNode(node: Node | undefined, test: ((node: Node) => boolean) | undefined, message?: string, stackCrawlMark?: AnyFunction): void;
    function assertOptionalNode<T extends Node, U extends T>(node: T, test: (node: T) => node is U, message?: string, stackCrawlMark?: AnyFunction): asserts node is U;
    function assertOptionalNode<T extends Node, U extends T>(node: T | undefined, test: (node: T) => node is U, message?: string, stackCrawlMark?: AnyFunction): asserts node is U | undefined;
    function assertOptionalNode(node: Node | undefined, test: ((node: Node) => boolean) | undefined, message?: string, stackCrawlMark?: AnyFunction): void;
    function assertOptionalToken<T extends Node, K extends SyntaxKind>(node: T, kind: K, message?: string, stackCrawlMark?: AnyFunction): asserts node is Extract<T, {
        readonly kind: K;
    }>;
    function assertOptionalToken<T extends Node, K extends SyntaxKind>(node: T | undefined, kind: K, message?: string, stackCrawlMark?: AnyFunction): asserts node is Extract<T, {
        readonly kind: K;
    }> | undefined;
    function assertOptionalToken(node: Node | undefined, kind: SyntaxKind | undefined, message?: string, stackCrawlMark?: AnyFunction): void;
    function assertMissingNode(node: Node | undefined, message?: string, stackCrawlMark?: AnyFunction): asserts node is undefined;
    /**
     * Asserts a value has the specified type in typespace only (does not perform a runtime assertion).
     * This is useful in cases where we switch on `node.kind` and can be reasonably sure the type is accurate, and
     * as a result can reduce the number of unnecessary casts.
     */
    function type<T>(value: unknown): asserts value is T;
    function getFunctionName(func: AnyFunction): any;
    function formatSymbol(symbol: Symbol): string;
    /**
     * Formats an enum value as a string for debugging and debug assertions.
     */
    function formatEnum(value: number | undefined, enumObject: any, isFlags?: boolean): string;
    function formatSyntaxKind(kind: SyntaxKind | undefined): string;
    function formatSnippetKind(kind: SnippetKind | undefined): string;
    function formatNodeFlags(flags: NodeFlags | undefined): string;
    function formatModifierFlags(flags: ModifierFlags | undefined): string;
    function formatTransformFlags(flags: TransformFlags | undefined): string;
    function formatEmitFlags(flags: EmitFlags | undefined): string;
    function formatSymbolFlags(flags: SymbolFlags | undefined): string;
    function formatTypeFlags(flags: TypeFlags | undefined): string;
    function formatSignatureFlags(flags: SignatureFlags | undefined): string;
    function formatObjectFlags(flags: ObjectFlags | undefined): string;
    function formatFlowFlags(flags: FlowFlags | undefined): string;
    function formatRelationComparisonResult(result: RelationComparisonResult | undefined): string;
    function formatCheckMode(mode: CheckMode | undefined): string;
    function formatSignatureCheckMode(mode: SignatureCheckMode | undefined): string;
    function formatTypeFacts(facts: TypeFacts | undefined): string;
    function attachFlowNodeDebugInfo(flowNode: FlowNodeBase): void;
    function attachNodeArrayDebugInfo(array: NodeArray<Node>): void;
    /**
     * Injects debug information into frequently used types.
     */
    function enableDebugInfo(): void;
    function formatVariance(varianceFlags: VarianceFlags): string;
    type DebugType = Type & {
        __debugTypeToString(): string;
    };
    class DebugTypeMapper {
        kind: TypeMapKind;
        __debugToString(): string;
    }
    function attachDebugPrototypeIfDebug(mapper: TypeMapper): TypeMapper;
    function printControlFlowGraph(flowNode: FlowNode): void;
    function formatControlFlowGraph(flowNode: FlowNode): string;
}
//# sourceMappingURL=debug.d.ts.map