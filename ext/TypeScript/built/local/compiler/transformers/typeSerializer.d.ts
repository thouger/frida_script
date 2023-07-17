import { AccessorDeclaration, ArrayLiteralExpression, Block, CaseBlock, ClassLikeDeclaration, ConditionalExpression, Expression, Identifier, MethodDeclaration, ModuleBlock, Node, ParameterDeclaration, PropertyAccessEntityNameExpression, PropertyDeclaration, SourceFile, TransformationContext, TypeNode, VoidExpression } from "../_namespaces/ts";
/** @internal */
export type SerializedEntityName = Identifier | PropertyAccessEntityNameExpression;
/** @internal */
export type SerializedTypeNode = SerializedEntityName | ConditionalExpression | VoidExpression;
/** @internal */
export interface RuntimeTypeSerializerContext {
    /** Specifies the current lexical block scope */
    currentLexicalScope: SourceFile | Block | ModuleBlock | CaseBlock;
    /** Specifies the containing `class`, but only when there is no other block scope between the current location and the `class`. */
    currentNameScope: ClassLikeDeclaration | undefined;
}
/** @internal */
export interface RuntimeTypeSerializer {
    /**
     * Serializes a type node for use with decorator type metadata.
     *
     * Types are serialized in the following fashion:
     * - Void types point to "undefined" (e.g. "void 0")
     * - Function and Constructor types point to the global "Function" constructor.
     * - Interface types with a call or construct signature types point to the global
     *   "Function" constructor.
     * - Array and Tuple types point to the global "Array" constructor.
     * - Type predicates and booleans point to the global "Boolean" constructor.
     * - String literal types and strings point to the global "String" constructor.
     * - Enum and number types point to the global "Number" constructor.
     * - Symbol types point to the global "Symbol" constructor.
     * - Type references to classes (or class-like variables) point to the constructor for the class.
     * - Anything else points to the global "Object" constructor.
     *
     * @param node The type node to serialize.
     */
    serializeTypeNode(serializerContext: RuntimeTypeSerializerContext, node: TypeNode): Expression;
    /**
     * Serializes the type of a node for use with decorator type metadata.
     * @param node The node that should have its type serialized.
     */
    serializeTypeOfNode(serializerContext: RuntimeTypeSerializerContext, node: PropertyDeclaration | ParameterDeclaration | AccessorDeclaration | ClassLikeDeclaration | MethodDeclaration): Expression;
    /**
     * Serializes the types of the parameters of a node for use with decorator type metadata.
     * @param node The node that should have its parameter types serialized.
     */
    serializeParameterTypesOfNode(serializerContext: RuntimeTypeSerializerContext, node: Node, container: ClassLikeDeclaration): ArrayLiteralExpression;
    /**
     * Serializes the return type of a node for use with decorator type metadata.
     * @param node The node that should have its return type serialized.
     */
    serializeReturnTypeOfNode(serializerContext: RuntimeTypeSerializerContext, node: Node): SerializedTypeNode;
}
/** @internal */
export declare function createRuntimeTypeSerializer(context: TransformationContext): RuntimeTypeSerializer;
//# sourceMappingURL=typeSerializer.d.ts.map