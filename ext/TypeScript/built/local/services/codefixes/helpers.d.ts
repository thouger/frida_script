import { ArrowFunction, Block, CallExpression, ClassLikeDeclaration, CodeFixContextBase, Expression, FunctionDeclaration, FunctionExpression, GetAccessorDeclaration, Identifier, LanguageServiceHost, MethodDeclaration, MethodSignature, Modifier, ModifierFlags, Node, NodeArray, NodeBuilderFlags, ObjectLiteralExpression, Program, PropertyAssignment, PropertyDeclaration, PropertyName, QuotePreference, ScriptTarget, SetAccessorDeclaration, Signature, SourceFile, Symbol, SymbolTracker, SyntaxKind, textChanges, TextSpan, TsConfigSourceFile, Type, TypeChecker, TypeNode, UserPreferences } from "../_namespaces/ts";
import { ImportAdder } from "../_namespaces/ts.codefix";
/**
 * Finds members of the resolved type that are missing in the class pointed to by class decl
 * and generates source code for the missing members.
 * @param possiblyMissingSymbols The collection of symbols to filter and then get insertions for.
 * @param importAdder If provided, type annotations will use identifier type references instead of ImportTypeNodes, and the missing imports will be added to the importAdder.
 * @returns Empty string iff there are no member insertions.
 *
 * @internal
 */
export declare function createMissingMemberNodes(classDeclaration: ClassLikeDeclaration, possiblyMissingSymbols: readonly Symbol[], sourceFile: SourceFile, context: TypeConstructionContext, preferences: UserPreferences, importAdder: ImportAdder | undefined, addClassElement: (node: AddNode) => void): void;
/** @internal */
export declare function getNoopSymbolTrackerWithResolver(context: TypeConstructionContext): SymbolTracker;
/** @internal */
export interface TypeConstructionContext {
    program: Program;
    host: LanguageServiceHost;
}
/** @internal */
export type AddNode = PropertyDeclaration | GetAccessorDeclaration | SetAccessorDeclaration | MethodDeclaration | FunctionExpression | ArrowFunction;
/** @internal */
export declare const enum PreserveOptionalFlags {
    Method = 1,
    Property = 2,
    All = 3
}
/**
 * `addClassElement` will not be called if we can't figure out a representation for `symbol` in `enclosingDeclaration`.
 * @param body If defined, this will be the body of the member node passed to `addClassElement`. Otherwise, the body will default to a stub.
 *
 * @internal
 */
export declare function addNewNodeForMemberSymbol(symbol: Symbol, enclosingDeclaration: ClassLikeDeclaration, sourceFile: SourceFile, context: TypeConstructionContext, preferences: UserPreferences, importAdder: ImportAdder | undefined, addClassElement: (node: AddNode) => void, body: Block | undefined, preserveOptional?: PreserveOptionalFlags, isAmbient?: boolean): void;
/** @internal */
export declare function createSignatureDeclarationFromSignature(kind: SyntaxKind.MethodDeclaration | SyntaxKind.FunctionExpression | SyntaxKind.ArrowFunction | SyntaxKind.FunctionDeclaration, context: TypeConstructionContext, quotePreference: QuotePreference, signature: Signature, body: Block | undefined, name: PropertyName | undefined, modifiers: NodeArray<Modifier> | undefined, optional: boolean | undefined, enclosingDeclaration: Node | undefined, importAdder: ImportAdder | undefined): FunctionDeclaration | MethodDeclaration | FunctionExpression | ArrowFunction | undefined;
/** @internal */
export declare function createSignatureDeclarationFromCallExpression(kind: SyntaxKind.MethodDeclaration | SyntaxKind.FunctionDeclaration | SyntaxKind.MethodSignature, context: CodeFixContextBase, importAdder: ImportAdder, call: CallExpression, name: Identifier | string, modifierFlags: ModifierFlags, contextNode: Node): MethodDeclaration | FunctionDeclaration | MethodSignature;
/** @internal */
export interface ArgumentTypeParameterAndConstraint {
    argumentType: Type;
    constraint?: TypeNode;
}
/** @internal */
export declare function typeToAutoImportableTypeNode(checker: TypeChecker, importAdder: ImportAdder, type: Type, contextNode: Node | undefined, scriptTarget: ScriptTarget, flags?: NodeBuilderFlags, tracker?: SymbolTracker): TypeNode | undefined;
/** @internal */
export declare function getArgumentTypesAndTypeParameters(checker: TypeChecker, importAdder: ImportAdder, instanceTypes: Type[], contextNode: Node | undefined, scriptTarget: ScriptTarget, flags?: NodeBuilderFlags, tracker?: SymbolTracker): {
    argumentTypeNodes: TypeNode[];
    argumentTypeParameters: [string, ArgumentTypeParameterAndConstraint | undefined][];
};
/** @internal */
export declare function createStubbedBody(text: string, quotePreference: QuotePreference): Block;
/** @internal */
export declare function setJsonCompilerOptionValues(changeTracker: textChanges.ChangeTracker, configFile: TsConfigSourceFile, options: [string, Expression][]): undefined;
/** @internal */
export declare function setJsonCompilerOptionValue(changeTracker: textChanges.ChangeTracker, configFile: TsConfigSourceFile, optionName: string, optionValue: Expression): void;
/** @internal */
export declare function createJsonPropertyAssignment(name: string, initializer: Expression): PropertyAssignment;
/** @internal */
export declare function findJsonProperty(obj: ObjectLiteralExpression, name: string): PropertyAssignment | undefined;
/**
 * Given a type node containing 'import("./a").SomeType<import("./b").OtherType<...>>',
 * returns an equivalent type reference node with any nested ImportTypeNodes also replaced
 * with type references, and a list of symbols that must be imported to use the type reference.
 *
 * @internal
 */
export declare function tryGetAutoImportableReferenceFromTypeNode(importTypeNode: TypeNode | undefined, scriptTarget: ScriptTarget): {
    typeNode: TypeNode;
    symbols: Symbol[];
} | undefined;
/** @internal */
export declare function importSymbols(importAdder: ImportAdder, symbols: readonly Symbol[]): void;
/** @internal */
export declare function findAncestorMatchingSpan(sourceFile: SourceFile, span: TextSpan): Node;
//# sourceMappingURL=helpers.d.ts.map