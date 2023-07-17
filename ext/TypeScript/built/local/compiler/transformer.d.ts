import { CompilerOptions, CustomTransformers, EmitHint, EmitHost, EmitOnly, EmitResolver, EmitTransformers, Node, NodeFactory, TransformationContext, TransformationResult, TransformerFactory } from "./_namespaces/ts";
/** @internal */
export declare const noTransformers: EmitTransformers;
/** @internal */
export declare function getTransformers(compilerOptions: CompilerOptions, customTransformers?: CustomTransformers, emitOnly?: boolean | EmitOnly): EmitTransformers;
/** @internal */
export declare function noEmitSubstitution(_hint: EmitHint, node: Node): Node;
/** @internal */
export declare function noEmitNotification(hint: EmitHint, node: Node, callback: (hint: EmitHint, node: Node) => void): void;
/**
 * Transforms an array of SourceFiles by passing them through each transformer.
 *
 * @param resolver The emit resolver provided by the checker.
 * @param host The emit host object used to interact with the file system.
 * @param options Compiler options to surface in the `TransformationContext`.
 * @param nodes An array of nodes to transform.
 * @param transforms An array of `TransformerFactory` callbacks.
 * @param allowDtsFiles A value indicating whether to allow the transformation of .d.ts files.
 *
 * @internal
 */
export declare function transformNodes<T extends Node>(resolver: EmitResolver | undefined, host: EmitHost | undefined, factory: NodeFactory, options: CompilerOptions, nodes: readonly T[], transformers: readonly TransformerFactory<T>[], allowDtsFiles: boolean): TransformationResult<T>;
/** @internal */
export declare const nullTransformationContext: TransformationContext;
//# sourceMappingURL=transformer.d.ts.map