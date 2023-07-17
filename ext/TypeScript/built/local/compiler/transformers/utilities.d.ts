import { __String, AllDecorators, BinaryOperator, Bundle, ClassDeclaration, ClassElement, ClassExpression, ClassLikeDeclaration, ClassStaticBlockDeclaration, CompilerOptions, CompoundAssignmentOperator, CoreTransformationContext, EmitResolver, ExportAssignment, ExportDeclaration, ExportSpecifier, Expression, Identifier, ImportDeclaration, ImportEqualsDeclaration, InitializedPropertyDeclaration, LogicalOperatorOrHigher, Node, NodeArray, PrivateIdentifier, PrivateIdentifierAccessorDeclaration, PrivateIdentifierAutoAccessorPropertyDeclaration, PrivateIdentifierMethodDeclaration, PropertyDeclaration, SourceFile, Statement, SuperCall, SyntaxKind, TransformationContext } from "../_namespaces/ts";
/** @internal */
export declare function getOriginalNodeId(node: Node): number;
/** @internal */
export interface ExternalModuleInfo {
    externalImports: (ImportDeclaration | ImportEqualsDeclaration | ExportDeclaration)[];
    externalHelpersImportDeclaration: ImportDeclaration | undefined;
    exportSpecifiers: Map<string, ExportSpecifier[]>;
    exportedBindings: Identifier[][];
    exportedNames: Identifier[] | undefined;
    exportEquals: ExportAssignment | undefined;
    hasExportStarsToExportValues: boolean;
}
/** @internal */
export declare function chainBundle(context: CoreTransformationContext, transformSourceFile: (x: SourceFile) => SourceFile): (x: SourceFile | Bundle) => SourceFile | Bundle;
/** @internal */
export declare function getExportNeedsImportStarHelper(node: ExportDeclaration): boolean;
/** @internal */
export declare function getImportNeedsImportStarHelper(node: ImportDeclaration): boolean;
/** @internal */
export declare function getImportNeedsImportDefaultHelper(node: ImportDeclaration): boolean;
/** @internal */
export declare function collectExternalModuleInfo(context: TransformationContext, sourceFile: SourceFile, resolver: EmitResolver, compilerOptions: CompilerOptions): ExternalModuleInfo;
/**
 * Used in the module transformer to check if an expression is reasonably without sideeffect,
 *  and thus better to copy into multiple places rather than to cache in a temporary variable
 *  - this is mostly subjective beyond the requirement that the expression not be sideeffecting
 *
 * @internal
 */
export declare function isSimpleCopiableExpression(expression: Expression): boolean;
/**
 * A simple inlinable expression is an expression which can be copied into multiple locations
 * without risk of repeating any sideeffects and whose value could not possibly change between
 * any such locations
 *
 * @internal
 */
export declare function isSimpleInlineableExpression(expression: Expression): boolean;
/** @internal */
export declare function isCompoundAssignment(kind: BinaryOperator): kind is CompoundAssignmentOperator;
/** @internal */
export declare function getNonAssignmentOperatorForCompoundAssignment(kind: CompoundAssignmentOperator): LogicalOperatorOrHigher | SyntaxKind.QuestionQuestionToken;
/**
 * @returns Contained super() call from descending into the statement ignoring parentheses, if that call exists.
 *
 * @internal
 */
export declare function getSuperCallFromStatement(statement: Statement): SuperCall | undefined;
/**
 * @returns The index (after prologue statements) of a super call, or -1 if not found.
 *
 * @internal
 */
export declare function findSuperStatementIndex(statements: NodeArray<Statement>, indexAfterLastPrologueStatement: number): number;
/**
 * Gets all the static or all the instance property declarations of a class
 *
 * @param node The class node.
 * @param isStatic A value indicating whether to get properties from the static or instance side of the class.
 *
 * @internal
 */
export declare function getProperties(node: ClassExpression | ClassDeclaration, requireInitializer: true, isStatic: boolean): readonly InitializedPropertyDeclaration[];
/** @internal */
export declare function getProperties(node: ClassExpression | ClassDeclaration, requireInitializer: boolean, isStatic: boolean): readonly PropertyDeclaration[];
/** @internal */
export declare function getStaticPropertiesAndClassStaticBlock(node: ClassExpression | ClassDeclaration): readonly (PropertyDeclaration | ClassStaticBlockDeclaration)[];
/** @internal */
export declare function getStaticPropertiesAndClassStaticBlock(node: ClassExpression | ClassDeclaration): readonly (PropertyDeclaration | ClassStaticBlockDeclaration)[];
/**
 * Gets a value indicating whether a class element is either a static or an instance property declaration with an initializer.
 *
 * @param member The class element node.
 * @param isStatic A value indicating whether the member should be a static or instance member.
 *
 * @internal
 */
export declare function isInitializedProperty(member: ClassElement): member is PropertyDeclaration & {
    initializer: Expression;
};
/**
 * Gets a value indicating whether a class element is a private instance method or accessor.
 *
 * @param member The class element node.
 *
 * @internal
 */
export declare function isNonStaticMethodOrAccessorWithPrivateName(member: ClassElement): member is PrivateIdentifierMethodDeclaration | PrivateIdentifierAccessorDeclaration | PrivateIdentifierAutoAccessorPropertyDeclaration;
/**
 * Gets an AllDecorators object containing the decorators for the class and the decorators for the
 * parameters of the constructor of the class.
 *
 * @param node The class node.
 *
 * @internal
 */
export declare function getAllDecoratorsOfClass(node: ClassLikeDeclaration): AllDecorators | undefined;
/**
 * Gets an AllDecorators object containing the decorators for the member and its parameters.
 *
 * @param parent The class node that contains the member.
 * @param member The class member.
 *
 * @internal
 */
export declare function getAllDecoratorsOfClassElement(member: ClassElement, parent: ClassLikeDeclaration, useLegacyDecorators: boolean): AllDecorators | undefined;
/** @internal */
export interface PrivateEnvironment<TData, TEntry> {
    readonly data: TData;
    /**
     * A mapping of private names to information needed for transformation.
     */
    identifiers?: Map<__String, TEntry>;
    /**
     * A mapping of generated private names to information needed for transformation.
     */
    generatedIdentifiers?: Map<Node, TEntry>;
}
/** @internal */
export interface LexicalEnvironment<in out TEnvData, TPrivateEnvData, TPrivateEntry> {
    data: TEnvData;
    privateEnv?: PrivateEnvironment<TPrivateEnvData, TPrivateEntry>;
    readonly previous: LexicalEnvironment<TEnvData, TPrivateEnvData, TPrivateEntry> | undefined;
}
/** @internal */
export declare function walkUpLexicalEnvironments<TEnvData, TPrivateEnvData, TPrivateEntry, U>(env: LexicalEnvironment<TEnvData, TPrivateEnvData, TPrivateEntry> | undefined, cb: (env: LexicalEnvironment<TEnvData, TPrivateEnvData, TPrivateEntry>) => U): U | undefined;
/** @internal */
export declare function newPrivateEnvironment<TData, TEntry>(data: TData): PrivateEnvironment<TData, TEntry>;
/** @internal */
export declare function getPrivateIdentifier<TData, TEntry>(privateEnv: PrivateEnvironment<TData, TEntry> | undefined, name: PrivateIdentifier): TEntry | undefined;
/** @internal */
export declare function setPrivateIdentifier<TData, TEntry>(privateEnv: PrivateEnvironment<TData, TEntry>, name: PrivateIdentifier, entry: TEntry): void;
/** @internal */
export declare function accessPrivateIdentifier<TEnvData, TPrivateEnvData, TPrivateEntry>(env: LexicalEnvironment<TEnvData, TPrivateEnvData, TPrivateEntry> | undefined, name: PrivateIdentifier): TPrivateEntry | undefined;
//# sourceMappingURL=utilities.d.ts.map