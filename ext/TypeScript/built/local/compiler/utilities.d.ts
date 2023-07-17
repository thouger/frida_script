import { __String, AccessExpression, AccessorDeclaration, AliasDeclarationNode, AllAccessorDeclarations, AmbientModuleDeclaration, AmpersandAmpersandEqualsToken, AnyImportOrBareOrAccessedRequire, AnyImportOrReExport, AnyImportSyntax, AnyValidImportOrReExport, ArrowFunction, AssignmentDeclarationKind, AssignmentExpression, AssignmentOperatorToken, BarBarEqualsToken, BinaryExpression, BindableObjectDefinePropertyCall, BindableStaticAccessExpression, BindableStaticElementAccessExpression, BindableStaticNameExpression, BindingElement, BindingElementOfBareOrAccessedRequire, Block, BundleFileSection, BundleFileTextLike, CallExpression, CallLikeExpression, CallSignatureDeclaration, CaseBlock, CaseClause, CatchClause, CharacterCodes, CheckFlags, ClassDeclaration, ClassElement, ClassExpression, ClassLikeDeclaration, ClassStaticBlockDeclaration, CommandLineOption, CommentDirective, CommentDirectivesMap, CommentRange, Comparison, CompilerOptions, ComputedPropertyName, ConstructorDeclaration, ConstructSignatureDeclaration, Declaration, DeclarationName, DeclarationWithTypeParameterChildren, DeclarationWithTypeParameters, DefaultClause, DestructuringAssignment, Diagnostic, DiagnosticArguments, DiagnosticCollection, DiagnosticMessage, DiagnosticMessageChain, DiagnosticRelatedInformation, DiagnosticWithDetachedLocation, DiagnosticWithLocation, DoStatement, DynamicNamedBinaryExpression, DynamicNamedDeclaration, ElementAccessExpression, EmitFlags, EmitHost, EmitResolver, EmitTextWriter, EntityName, EntityNameExpression, EntityNameOrEntityNameExpression, EnumDeclaration, EqualityComparer, EqualsToken, ExportAssignment, ExportDeclaration, ExportSpecifier, Expression, ExpressionWithTypeArguments, Extension, ExternalModuleReference, FileExtensionInfo, FileWatcher, ForInStatement, ForOfStatement, ForStatement, FunctionBody, FunctionDeclaration, FunctionExpression, FunctionLikeDeclaration, GetAccessorDeclaration, GetCanonicalFileName, HasExpressionInitializer, HasFlowNode, HasJSDoc, HasModifiers, HasTypeArguments, HeritageClause, Identifier, IdentifierTypePredicate, IfStatement, ImportCall, ImportClause, ImportDeclaration, ImportEqualsDeclaration, ImportMetaProperty, ImportSpecifier, ImportTypeNode, IndexInfo, IndexSignatureDeclaration, InitializedVariableDeclaration, InterfaceDeclaration, InternalEmitFlags, JSDoc, JSDocCallbackTag, JSDocEnumTag, JSDocMemberName, JSDocParameterTag, JSDocPropertyLikeTag, JSDocSatisfiesExpression, JSDocSignature, JSDocTag, JSDocTemplateTag, JSDocTypedefTag, JsonSourceFile, JsxAttributeName, JsxChild, JsxNamespacedName, JsxTagNameExpression, KeywordSyntaxKind, LabeledStatement, LanguageVariant, LateVisibilityPaintedStatement, LiteralImportTypeNode, LiteralLikeElementAccessExpression, LiteralLikeNode, LogicalOperator, LogicalOrCoalescingAssignmentOperator, MapLike, MemberName, MethodDeclaration, MethodSignature, ModeAwareCache, ModifierFlags, ModifierLike, ModuleDeclaration, ModuleDetectionKind, ModuleKind, ModuleResolutionKind, MultiMap, NamedImportsOrExports, NamespaceExport, NamespaceImport, Node, NodeArray, NodeFlags, NoSubstitutionTemplateLiteral, NumericLiteral, ObjectFlags, ObjectLiteralElement, ObjectLiteralExpression, ObjectTypeDeclaration, PackageId, ParameterDeclaration, ParenthesizedTypeNode, Path, Pattern, PrefixUnaryExpression, PrinterOptions, PrintHandlers, PrivateIdentifier, ProjectReference, PrologueDirective, PropertyAccessEntityNameExpression, PropertyAccessExpression, PropertyAssignment, PropertyDeclaration, PropertyName, PropertyNameLiteral, PropertySignature, PseudoBigInt, PunctuationOrKeywordSyntaxKind, PunctuationSyntaxKind, QualifiedName, QuestionQuestionEqualsToken, ReadonlyCollection, ReadonlyTextRange, RequireOrImportCall, RequireVariableStatement, ResolutionMode, ResolutionNameAndModeGetter, ResolvedModuleFull, ResolvedModuleWithFailedLookupLocations, ResolvedTypeReferenceDirective, ResolvedTypeReferenceDirectiveWithFailedLookupLocations, ReturnStatement, ScriptKind, ScriptTarget, SetAccessorDeclaration, ShorthandPropertyAssignment, Signature, SignatureDeclaration, SignatureFlags, SourceFile, SourceFileLike, SourceFileMayBeEmittedHost, SourceMapSource, Statement, StringLiteral, StringLiteralLike, SuperCall, SuperExpression, SuperProperty, SwitchStatement, Symbol, SymbolFlags, SymbolTable, SyntaxKind, TemplateLiteral, TextRange, TextSpan, ThisTypePredicate, Token, TransientSymbol, TriviaSyntaxKind, TryStatement, TsConfigSourceFile, Type, TypeAliasDeclaration, TypeChecker, TypeCheckerHost, TypeElement, TypeFlags, TypeNode, TypeNodeSyntaxKind, TypeParameterDeclaration, TypePredicate, TypeReferenceNode, UserPreferences, VariableDeclaration, VariableDeclarationInitializedTo, VariableDeclarationList, VariableLikeDeclaration, VariableStatement, WhileStatement, WithStatement, WrappedExpression, WriteFileCallback, WriteFileCallbackData, YieldExpression } from "./_namespaces/ts";
/** @internal */
export declare const resolvingEmptyArray: never[];
/** @internal */
export declare const externalHelpersModuleNameText = "tslib";
/** @internal */
export declare const defaultMaximumTruncationLength = 160;
/** @internal */
export declare const noTruncationMaximumTruncationLength = 1000000;
/** @internal */
export declare function getDeclarationOfKind<T extends Declaration>(symbol: Symbol, kind: T["kind"]): T | undefined;
/** @internal */
export declare function getDeclarationsOfKind<T extends Declaration>(symbol: Symbol, kind: T["kind"]): T[];
/** @internal */
export declare function createSymbolTable(symbols?: readonly Symbol[]): SymbolTable;
/** @internal */
export declare function isTransientSymbol(symbol: Symbol): symbol is TransientSymbol;
/** @internal */
export declare function changesAffectModuleResolution(oldOptions: CompilerOptions, newOptions: CompilerOptions): boolean;
/** @internal */
export declare function optionsHaveModuleResolutionChanges(oldOptions: CompilerOptions, newOptions: CompilerOptions): boolean;
/** @internal */
export declare function changesAffectingProgramStructure(oldOptions: CompilerOptions, newOptions: CompilerOptions): boolean;
/** @internal */
export declare function optionsHaveChanges(oldOptions: CompilerOptions, newOptions: CompilerOptions, optionDeclarations: readonly CommandLineOption[]): boolean;
/** @internal */
export declare function forEachAncestor<T>(node: Node, callback: (n: Node) => T | undefined | "quit"): T | undefined;
/**
 * Calls `callback` for each entry in the map, returning the first truthy result.
 * Use `map.forEach` instead for normal iteration.
 *
 * @internal
 */
export declare function forEachEntry<K, V, U>(map: ReadonlyMap<K, V>, callback: (value: V, key: K) => U | undefined): U | undefined;
/**
 * `forEachEntry` for just keys.
 *
 * @internal
 */
export declare function forEachKey<K, T>(map: ReadonlyCollection<K>, callback: (key: K) => T | undefined): T | undefined;
/**
 * Copy entries from `source` to `target`.
 *
 * @internal
 */
export declare function copyEntries<K, V>(source: ReadonlyMap<K, V>, target: Map<K, V>): void;
/** @internal */
export declare function usingSingleLineStringWriter(action: (writer: EmitTextWriter) => void): string;
/** @internal */
export declare function getFullWidth(node: Node): number;
/** @internal */
export declare function getResolvedModule(sourceFile: SourceFile | undefined, moduleNameText: string, mode: ResolutionMode): ResolvedModuleFull | undefined;
/** @internal */
export declare function setResolvedModule(sourceFile: SourceFile, moduleNameText: string, resolvedModule: ResolvedModuleWithFailedLookupLocations, mode: ResolutionMode): void;
/** @internal */
export declare function setResolvedTypeReferenceDirective(sourceFile: SourceFile, typeReferenceDirectiveName: string, resolvedTypeReferenceDirective: ResolvedTypeReferenceDirectiveWithFailedLookupLocations, mode: ResolutionMode): void;
/** @internal */
export declare function getResolvedTypeReferenceDirective(sourceFile: SourceFile | undefined, typeReferenceDirectiveName: string, mode: ResolutionMode): ResolvedTypeReferenceDirective | undefined;
/** @internal */
export declare function projectReferenceIsEqualTo(oldRef: ProjectReference, newRef: ProjectReference): boolean;
/** @internal */
export declare function moduleResolutionIsEqualTo(oldResolution: ResolvedModuleWithFailedLookupLocations, newResolution: ResolvedModuleWithFailedLookupLocations): boolean;
/** @internal */
export declare function createModuleNotFoundChain(sourceFile: SourceFile, host: TypeCheckerHost, moduleReference: string, mode: ResolutionMode, packageName: string): DiagnosticMessageChain;
/** @internal */
export declare function packageIdToPackageName({ name, subModuleName }: PackageId): string;
/** @internal */
export declare function packageIdToString(packageId: PackageId): string;
/** @internal */
export declare function typeDirectiveIsEqualTo(oldResolution: ResolvedTypeReferenceDirectiveWithFailedLookupLocations, newResolution: ResolvedTypeReferenceDirectiveWithFailedLookupLocations): boolean;
/** @internal */
export declare function hasChangesInResolutions<K, V>(names: readonly K[], newSourceFile: SourceFile, newResolutions: readonly V[], oldResolutions: ModeAwareCache<V> | undefined, comparer: (oldResolution: V, newResolution: V) => boolean, nameAndModeGetter: ResolutionNameAndModeGetter<K, SourceFile>): boolean;
/** @internal */
export declare function containsParseError(node: Node): boolean;
/** @internal */
export declare function getSourceFileOfNode(node: Node): SourceFile;
/** @internal */
export declare function getSourceFileOfNode(node: Node | undefined): SourceFile | undefined;
/** @internal */
export declare function getSourceFileOfModule(module: Symbol): SourceFile | undefined;
/** @internal */
export declare function isPlainJsFile(file: SourceFile | undefined, checkJs: boolean | undefined): boolean;
/** @internal */
export declare function isStatementWithLocals(node: Node): boolean;
/** @internal */
export declare function getStartPositionOfLine(line: number, sourceFile: SourceFileLike): number;
/** @internal */
export declare function nodePosToString(node: Node): string;
/** @internal */
export declare function getEndLinePosition(line: number, sourceFile: SourceFileLike): number;
/**
 * Returns a value indicating whether a name is unique globally or within the current file.
 * Note: This does not consider whether a name appears as a free identifier or not, so at the expression `x.y` this includes both `x` and `y`.
 *
 * @internal
 */
export declare function isFileLevelUniqueName(sourceFile: SourceFile, name: string, hasGlobalName?: PrintHandlers["hasGlobalName"]): boolean;
/** @internal */
export declare function nodeIsMissing(node: Node | undefined): boolean;
/** @internal */
export declare function nodeIsPresent(node: Node | undefined): boolean;
/**
 * Tests whether `child` is a grammar error on `parent`.
 * @internal
 */
export declare function isGrammarError(parent: Node, child: Node | NodeArray<Node>): boolean;
/**
 * Prepends statements to an array while taking care of prologue directives.
 *
 * @internal
 */
export declare function insertStatementsAfterStandardPrologue<T extends Statement>(to: T[], from: readonly T[] | undefined): T[];
/** @internal */
export declare function insertStatementsAfterCustomPrologue<T extends Statement>(to: T[], from: readonly T[] | undefined): T[];
/**
 * Prepends statements to an array while taking care of prologue directives.
 *
 * @internal
 */
export declare function insertStatementAfterStandardPrologue<T extends Statement>(to: T[], statement: T | undefined): T[];
/** @internal */
export declare function insertStatementAfterCustomPrologue<T extends Statement>(to: T[], statement: T | undefined): T[];
/**
 * Determine if the given comment is a triple-slash
 *
 * @return true if the comment is a triple-slash comment else false
 *
 * @internal
 */
export declare function isRecognizedTripleSlashComment(text: string, commentPos: number, commentEnd: number): boolean;
/** @internal */
export declare function isPinnedComment(text: string, start: number): boolean;
/** @internal */
export declare function createCommentDirectivesMap(sourceFile: SourceFile, commentDirectives: CommentDirective[]): CommentDirectivesMap;
/** @internal */
export declare function getTokenPosOfNode(node: Node, sourceFile?: SourceFileLike, includeJsDoc?: boolean): number;
/** @internal */
export declare function getNonDecoratorTokenPosOfNode(node: Node, sourceFile?: SourceFileLike): number;
/** @internal */
export declare function getSourceTextOfNodeFromSourceFile(sourceFile: SourceFile, node: Node, includeTrivia?: boolean): string;
/** @internal */
export declare function isExportNamespaceAsDefaultDeclaration(node: Node): boolean;
/** @internal */
export declare function getTextOfNodeFromSourceText(sourceText: string, node: Node, includeTrivia?: boolean): string;
/** @internal */
export declare function getTextOfNode(node: Node, includeTrivia?: boolean): string;
/**
 * Note: it is expected that the `nodeArray` and the `node` are within the same file.
 * For example, searching for a `SourceFile` in a `SourceFile[]` wouldn't work.
 *
 * @internal
 */
export declare function indexOfNode(nodeArray: readonly Node[], node: Node): number;
/**
 * Gets flags that control emit behavior of a node.
 *
 * @internal
 */
export declare function getEmitFlags(node: Node): EmitFlags;
/**
 * Gets flags that control emit behavior of a node.
 *
 * @internal
 */
export declare function getInternalEmitFlags(node: Node): InternalEmitFlags;
/** @internal */
export type ScriptTargetFeatures = ReadonlyMap<string, ReadonlyMap<string, string[]>>;
/** @internal */
export declare function getScriptTargetFeatures(): ScriptTargetFeatures;
/** @internal */
export declare const enum GetLiteralTextFlags {
    None = 0,
    NeverAsciiEscape = 1,
    JsxAttributeEscape = 2,
    TerminateUnterminatedLiterals = 4,
    AllowNumericSeparator = 8
}
/** @internal */
export declare function getLiteralText(node: LiteralLikeNode, sourceFile: SourceFile | undefined, flags: GetLiteralTextFlags): string;
/** @internal */
export declare function getTextOfConstantValue(value: string | number): string;
/** @internal */
export declare function makeIdentifierFromModuleName(moduleName: string): string;
/** @internal */
export declare function isBlockOrCatchScoped(declaration: Declaration): boolean;
/** @internal */
export declare function isCatchClauseVariableDeclarationOrBindingElement(declaration: Declaration): boolean;
/** @internal */
export declare function isAmbientModule(node: Node): node is AmbientModuleDeclaration;
/** @internal */
export declare function isModuleWithStringLiteralName(node: Node): node is ModuleDeclaration;
/** @internal */
export declare function isNonGlobalAmbientModule(node: Node): node is ModuleDeclaration & {
    name: StringLiteral;
};
/**
 * An effective module (namespace) declaration is either
 * 1. An actual declaration: namespace X { ... }
 * 2. A Javascript declaration, which is:
 *    An identifier in a nested property access expression: Y in `X.Y.Z = { ... }`
 *
 * @internal
 */
export declare function isEffectiveModuleDeclaration(node: Node): boolean;
/**
 * Given a symbol for a module, checks that it is a shorthand ambient module.
 *
 * @internal
 */
export declare function isShorthandAmbientModuleSymbol(moduleSymbol: Symbol): boolean;
/** @internal */
export declare function isBlockScopedContainerTopLevel(node: Node): boolean;
/** @internal */
export declare function isGlobalScopeAugmentation(module: ModuleDeclaration): boolean;
/** @internal */
export declare function isExternalModuleAugmentation(node: Node): node is AmbientModuleDeclaration;
/** @internal */
export declare function isModuleAugmentationExternal(node: AmbientModuleDeclaration): boolean;
/** @internal */
export declare function getNonAugmentationDeclaration(symbol: Symbol): Declaration | undefined;
/** @internal */
export declare function isEffectiveExternalModule(node: SourceFile, compilerOptions: CompilerOptions): boolean;
/**
 * Returns whether the source file will be treated as if it were in strict mode at runtime.
 *
 * @internal
 */
export declare function isEffectiveStrictModeSourceFile(node: SourceFile, compilerOptions: CompilerOptions): boolean;
/** @internal */
export declare function isAmbientPropertyDeclaration(node: PropertyDeclaration): boolean;
/** @internal */
export declare function isBlockScope(node: Node, parentNode: Node | undefined): boolean;
/** @internal */
export declare function isDeclarationWithTypeParameters(node: Node): node is DeclarationWithTypeParameters;
/** @internal */
export declare function isDeclarationWithTypeParameterChildren(node: Node): node is DeclarationWithTypeParameterChildren;
/** @internal */
export declare function isAnyImportSyntax(node: Node): node is AnyImportSyntax;
/** @internal */
export declare function isAnyImportOrBareOrAccessedRequire(node: Node): node is AnyImportOrBareOrAccessedRequire;
/** @internal */
export declare function isLateVisibilityPaintedStatement(node: Node): node is LateVisibilityPaintedStatement;
/** @internal */
export declare function hasPossibleExternalModuleReference(node: Node): node is AnyImportOrReExport | ModuleDeclaration | ImportTypeNode | ImportCall;
/** @internal */
export declare function isAnyImportOrReExport(node: Node): node is AnyImportOrReExport;
/** @internal */
export declare function getEnclosingBlockScopeContainer(node: Node): Node;
/** @internal */
export declare function forEachEnclosingBlockScopeContainer(node: Node, cb: (container: Node) => void): void;
/** @internal */
export declare function declarationNameToString(name: DeclarationName | QualifiedName | undefined): string;
/** @internal */
export declare function getNameFromIndexInfo(info: IndexInfo): string | undefined;
/** @internal */
export declare function isComputedNonLiteralName(name: PropertyName): boolean;
/** @internal */
export declare function tryGetTextOfPropertyName(name: PropertyName | NoSubstitutionTemplateLiteral | JsxAttributeName): __String | undefined;
/** @internal */
export declare function getTextOfPropertyName(name: PropertyName | NoSubstitutionTemplateLiteral | JsxAttributeName): __String;
/** @internal */
export declare function entityNameToString(name: EntityNameOrEntityNameExpression | JSDocMemberName | JsxTagNameExpression | PrivateIdentifier): string;
/** @internal */
export declare function createDiagnosticForNode(node: Node, message: DiagnosticMessage, ...args: DiagnosticArguments): DiagnosticWithLocation;
/** @internal */
export declare function createDiagnosticForNodeArray(sourceFile: SourceFile, nodes: NodeArray<Node>, message: DiagnosticMessage, ...args: DiagnosticArguments): DiagnosticWithLocation;
/** @internal */
export declare function createDiagnosticForNodeInSourceFile(sourceFile: SourceFile, node: Node, message: DiagnosticMessage, ...args: DiagnosticArguments): DiagnosticWithLocation;
/** @internal */
export declare function createDiagnosticForNodeFromMessageChain(sourceFile: SourceFile, node: Node, messageChain: DiagnosticMessageChain, relatedInformation?: DiagnosticRelatedInformation[]): DiagnosticWithLocation;
/** @internal */
export declare function createDiagnosticForNodeArrayFromMessageChain(sourceFile: SourceFile, nodes: NodeArray<Node>, messageChain: DiagnosticMessageChain, relatedInformation?: DiagnosticRelatedInformation[]): DiagnosticWithLocation;
/** @internal */
export declare function createFileDiagnosticFromMessageChain(file: SourceFile, start: number, length: number, messageChain: DiagnosticMessageChain, relatedInformation?: DiagnosticRelatedInformation[]): DiagnosticWithLocation;
/** @internal */
export declare function createDiagnosticForFileFromMessageChain(sourceFile: SourceFile, messageChain: DiagnosticMessageChain, relatedInformation?: DiagnosticRelatedInformation[]): DiagnosticWithLocation;
/** @internal */
export declare function createDiagnosticMessageChainFromDiagnostic(diagnostic: DiagnosticRelatedInformation): DiagnosticMessageChain;
/** @internal */
export declare function createDiagnosticForRange(sourceFile: SourceFile, range: TextRange, message: DiagnosticMessage): DiagnosticWithLocation;
/** @internal */
export declare function getSpanOfTokenAtPosition(sourceFile: SourceFile, pos: number): TextSpan;
/** @internal */
export declare function scanTokenAtPosition(sourceFile: SourceFile, pos: number): SyntaxKind;
/** @internal */
export declare function getErrorSpanForNode(sourceFile: SourceFile, node: Node): TextSpan;
/** @internal */
export declare function isExternalOrCommonJsModule(file: SourceFile): boolean;
/** @internal */
export declare function isJsonSourceFile(file: SourceFile): file is JsonSourceFile;
/** @internal */
export declare function isEnumConst(node: EnumDeclaration): boolean;
/** @internal */
export declare function isDeclarationReadonly(declaration: Declaration): boolean;
/** @internal */
export declare function isVarConst(node: VariableDeclaration | VariableDeclarationList): boolean;
/** @internal */
export declare function isLet(node: Node): boolean;
/** @internal */
export declare function isSuperCall(n: Node): n is SuperCall;
/** @internal */
export declare function isImportCall(n: Node): n is ImportCall;
/** @internal */
export declare function isImportMeta(n: Node): n is ImportMetaProperty;
/** @internal */
export declare function isLiteralImportTypeNode(n: Node): n is LiteralImportTypeNode;
/** @internal */
export declare function isPrologueDirective(node: Node): node is PrologueDirective;
/** @internal */
export declare function isCustomPrologue(node: Statement): boolean;
/** @internal */
export declare function isHoistedFunction(node: Statement): boolean;
/** @internal */
export declare function isHoistedVariableStatement(node: Statement): boolean;
/** @internal */
export declare function getLeadingCommentRangesOfNode(node: Node, sourceFileOfNode: SourceFile): CommentRange[] | undefined;
/** @internal */
export declare function getJSDocCommentRanges(node: Node, text: string): CommentRange[] | undefined;
/** @internal */
export declare const fullTripleSlashReferencePathRegEx: RegExp;
/** @internal */
export declare const fullTripleSlashAMDReferencePathRegEx: RegExp;
/** @internal */
export declare function isPartOfTypeNode(node: Node): boolean;
/** @internal */
export declare function isChildOfNodeWithKind(node: Node, kind: SyntaxKind): boolean;
/** @internal */
export declare function forEachReturnStatement<T>(body: Block | Statement, visitor: (stmt: ReturnStatement) => T): T | undefined;
/** @internal */
export declare function forEachYieldExpression(body: Block, visitor: (expr: YieldExpression) => void): void;
/**
 * Gets the most likely element type for a TypeNode. This is not an exhaustive test
 * as it assumes a rest argument can only be an array type (either T[], or Array<T>).
 *
 * @param node The type node.
 *
 * @internal
 */
export declare function getRestParameterElementType(node: TypeNode | undefined): TypeNode | undefined;
/** @internal */
export declare function getMembersOfDeclaration(node: Declaration): NodeArray<ClassElement | TypeElement | ObjectLiteralElement> | undefined;
/** @internal */
export declare function isVariableLike(node: Node): node is VariableLikeDeclaration;
/** @internal */
export declare function isVariableLikeOrAccessor(node: Node): node is AccessorDeclaration | VariableLikeDeclaration;
/** @internal */
export declare function isVariableDeclarationInVariableStatement(node: VariableDeclaration): boolean;
/** @internal */
export declare function isCommonJsExportedExpression(node: Node): boolean;
/** @internal */
export declare function isCommonJsExportPropertyAssignment(node: Node): boolean;
/** @internal */
export declare function isValidESSymbolDeclaration(node: Node): boolean;
/** @internal */
export declare function introducesArgumentsExoticObject(node: Node): boolean;
/** @internal */
export declare function unwrapInnermostStatementOfLabel(node: LabeledStatement, beforeUnwrapLabelCallback?: (node: LabeledStatement) => void): Statement;
/** @internal */
export declare function isFunctionBlock(node: Node): boolean;
/** @internal */
export declare function isObjectLiteralMethod(node: Node): node is MethodDeclaration;
/** @internal */
export declare function isObjectLiteralOrClassExpressionMethodOrAccessor(node: Node): node is MethodDeclaration | AccessorDeclaration;
/** @internal */
export declare function isIdentifierTypePredicate(predicate: TypePredicate): predicate is IdentifierTypePredicate;
/** @internal */
export declare function isThisTypePredicate(predicate: TypePredicate): predicate is ThisTypePredicate;
/** @internal */
export declare function forEachPropertyAssignment<T>(objectLiteral: ObjectLiteralExpression | undefined, key: string, callback: (property: PropertyAssignment) => T | undefined, key2?: string): T | undefined;
/** @internal */
export declare function getPropertyArrayElementValue(objectLiteral: ObjectLiteralExpression, propKey: string, elementValue: string): StringLiteral | undefined;
/** @internal */
export declare function getTsConfigObjectLiteralExpression(tsConfigSourceFile: TsConfigSourceFile | undefined): ObjectLiteralExpression | undefined;
/** @internal */
export declare function getTsConfigPropArrayElementValue(tsConfigSourceFile: TsConfigSourceFile | undefined, propKey: string, elementValue: string): StringLiteral | undefined;
/** @internal */
export declare function forEachTsConfigPropArray<T>(tsConfigSourceFile: TsConfigSourceFile | undefined, propKey: string, callback: (property: PropertyAssignment) => T | undefined): T | undefined;
/** @internal */
export declare function getContainingFunction(node: Node): SignatureDeclaration | undefined;
/** @internal */
export declare function getContainingFunctionDeclaration(node: Node): FunctionLikeDeclaration | undefined;
/** @internal */
export declare function getContainingClass(node: Node): ClassLikeDeclaration | undefined;
/** @internal */
export declare function getContainingClassStaticBlock(node: Node): Node | undefined;
/** @internal */
export declare function getContainingFunctionOrClassStaticBlock(node: Node): SignatureDeclaration | ClassStaticBlockDeclaration | undefined;
/** @internal */
export type ThisContainer = FunctionDeclaration | FunctionExpression | ModuleDeclaration | ClassStaticBlockDeclaration | PropertyDeclaration | PropertySignature | MethodDeclaration | MethodSignature | ConstructorDeclaration | GetAccessorDeclaration | SetAccessorDeclaration | CallSignatureDeclaration | ConstructSignatureDeclaration | IndexSignatureDeclaration | EnumDeclaration | SourceFile;
/** @internal */
export declare function getThisContainer(node: Node, includeArrowFunctions: false, includeClassComputedPropertyName: false): ThisContainer;
/** @internal */
export declare function getThisContainer(node: Node, includeArrowFunctions: false, includeClassComputedPropertyName: boolean): ThisContainer | ComputedPropertyName;
/** @internal */
export declare function getThisContainer(node: Node, includeArrowFunctions: boolean, includeClassComputedPropertyName: false): ThisContainer | ArrowFunction;
/** @internal */
export declare function getThisContainer(node: Node, includeArrowFunctions: boolean, includeClassComputedPropertyName: boolean): ThisContainer | ArrowFunction | ComputedPropertyName;
/**
 * @returns Whether the node creates a new 'this' scope for its children.
 *
 * @internal
 */
export declare function isThisContainerOrFunctionBlock(node: Node): boolean;
/** @internal */
export declare function isInTopLevelContext(node: Node): boolean;
/** @internal */
export declare function getNewTargetContainer(node: Node): FunctionExpression | FunctionDeclaration | ConstructorDeclaration | undefined;
/** @internal */
export type SuperContainer = PropertyDeclaration | PropertySignature | MethodDeclaration | MethodSignature | ConstructorDeclaration | GetAccessorDeclaration | SetAccessorDeclaration | ClassStaticBlockDeclaration;
/** @internal */
export type SuperContainerOrFunctions = SuperContainer | FunctionDeclaration | FunctionExpression | ArrowFunction;
/**
 * Given an super call/property node, returns the closest node where
 * - a super call/property access is legal in the node and not legal in the parent node the node.
 *   i.e. super call is legal in constructor but not legal in the class body.
 * - the container is an arrow function (so caller might need to call getSuperContainer again in case it needs to climb higher)
 * - a super call/property is definitely illegal in the container (but might be legal in some subnode)
 *   i.e. super property access is illegal in function declaration but can be legal in the statement list
 *
 * @internal
 */
export declare function getSuperContainer(node: Node, stopOnFunctions: false): SuperContainer | undefined;
/** @internal */
export declare function getSuperContainer(node: Node, stopOnFunctions: boolean): SuperContainerOrFunctions | undefined;
/** @internal */
export declare function getImmediatelyInvokedFunctionExpression(func: Node): CallExpression | undefined;
/** @internal */
export declare function isSuperOrSuperProperty(node: Node): node is SuperExpression | SuperProperty;
/**
 * Determines whether a node is a property or element access expression for `super`.
 *
 * @internal
 */
export declare function isSuperProperty(node: Node): node is SuperProperty;
/**
 * Determines whether a node is a property or element access expression for `this`.
 *
 * @internal
 */
export declare function isThisProperty(node: Node): boolean;
/** @internal */
export declare function isThisInitializedDeclaration(node: Node | undefined): boolean;
/** @internal */
export declare function isThisInitializedObjectBindingExpression(node: Node | undefined): boolean;
/** @internal */
export declare function getEntityNameFromTypeNode(node: TypeNode): EntityNameOrEntityNameExpression | undefined;
/** @internal */
export declare function getInvokedExpression(node: CallLikeExpression): Expression | JsxTagNameExpression;
/** @internal */
export declare function nodeCanBeDecorated(useLegacyDecorators: boolean, node: ClassDeclaration): true;
/** @internal */
export declare function nodeCanBeDecorated(useLegacyDecorators: boolean, node: ClassExpression): boolean;
/** @internal */
export declare function nodeCanBeDecorated(useLegacyDecorators: boolean, node: ClassElement, parent: Node): boolean;
/** @internal */
export declare function nodeCanBeDecorated(useLegacyDecorators: boolean, node: Node, parent: Node, grandparent: Node): boolean;
/** @internal */
export declare function nodeIsDecorated(useLegacyDecorators: boolean, node: ClassDeclaration | ClassExpression): boolean;
/** @internal */
export declare function nodeIsDecorated(useLegacyDecorators: boolean, node: ClassElement, parent: Node): boolean;
/** @internal */
export declare function nodeIsDecorated(useLegacyDecorators: boolean, node: Node, parent: Node, grandparent: Node): boolean;
/** @internal */
export declare function nodeOrChildIsDecorated(useLegacyDecorators: boolean, node: ClassDeclaration | ClassExpression): boolean;
/** @internal */
export declare function nodeOrChildIsDecorated(useLegacyDecorators: boolean, node: ClassElement, parent: Node): boolean;
/** @internal */
export declare function nodeOrChildIsDecorated(useLegacyDecorators: boolean, node: Node, parent: Node, grandparent: Node): boolean;
/** @internal */
export declare function childIsDecorated(useLegacyDecorators: boolean, node: ClassDeclaration | ClassExpression): boolean;
/** @internal */
export declare function childIsDecorated(useLegacyDecorators: boolean, node: Node, parent: Node): boolean;
/** @internal */
export declare function classOrConstructorParameterIsDecorated(useLegacyDecorators: boolean, node: ClassDeclaration | ClassExpression): boolean;
/** @internal */
export declare function classElementOrClassElementParameterIsDecorated(useLegacyDecorators: boolean, node: ClassElement, parent: ClassDeclaration | ClassExpression): boolean;
/** @internal */
export declare function isEmptyStringLiteral(node: StringLiteral): boolean;
/** @internal */
export declare function isJSXTagName(node: Node): boolean;
/** @internal */
export declare function isExpressionNode(node: Node): boolean;
/** @internal */
export declare function isInExpressionContext(node: Node): boolean;
/** @internal */
export declare function isPartOfTypeQuery(node: Node): boolean;
/** @internal */
export declare function isNamespaceReexportDeclaration(node: Node): boolean;
/** @internal */
export declare function isExternalModuleImportEqualsDeclaration(node: Node): node is ImportEqualsDeclaration & {
    moduleReference: ExternalModuleReference;
};
/** @internal */
export declare function getExternalModuleImportEqualsDeclarationExpression(node: Node): Expression;
/** @internal */
export declare function getExternalModuleRequireArgument(node: Node): false | StringLiteral;
/** @internal */
export declare function isInternalModuleImportEqualsDeclaration(node: Node): node is ImportEqualsDeclaration;
/** @internal */
export declare function isSourceFileJS(file: SourceFile): boolean;
/** @internal */
export declare function isSourceFileNotJS(file: SourceFile): boolean;
/** @internal */
export declare function isInJSFile(node: Node | undefined): boolean;
/** @internal */
export declare function isInJsonFile(node: Node | undefined): boolean;
/** @internal */
export declare function isSourceFileNotJson(file: SourceFile): boolean;
/** @internal */
export declare function isInJSDoc(node: Node | undefined): boolean;
/** @internal */
export declare function isJSDocIndexSignature(node: TypeReferenceNode | ExpressionWithTypeArguments): boolean | undefined;
/**
 * Returns true if the node is a CallExpression to the identifier 'require' with
 * exactly one argument (of the form 'require("name")').
 * This function does not test if the node is in a JavaScript file or not.
 *
 * @internal
 */
export declare function isRequireCall(callExpression: Node, requireStringLiteralLikeArgument: true): callExpression is RequireOrImportCall & {
    expression: Identifier;
    arguments: [StringLiteralLike];
};
/** @internal */
export declare function isRequireCall(callExpression: Node, requireStringLiteralLikeArgument: boolean): callExpression is CallExpression;
/**
 * Returns true if the node is a VariableDeclaration initialized to a require call (see `isRequireCall`).
 * This function does not test if the node is in a JavaScript file or not.
 *
 * @internal
 */
export declare function isVariableDeclarationInitializedToRequire(node: Node): node is VariableDeclarationInitializedTo<RequireOrImportCall>;
/**
 * Like {@link isVariableDeclarationInitializedToRequire} but allows things like `require("...").foo.bar` or `require("...")["baz"]`.
 *
 * @internal
 */
export declare function isVariableDeclarationInitializedToBareOrAccessedRequire(node: Node): node is VariableDeclarationInitializedTo<RequireOrImportCall | AccessExpression>;
/** @internal */
export declare function isBindingElementOfBareOrAccessedRequire(node: Node): node is BindingElementOfBareOrAccessedRequire;
/** @internal */
export declare function isRequireVariableStatement(node: Node): node is RequireVariableStatement;
/** @internal */
export declare function isSingleOrDoubleQuote(charCode: number): boolean;
/** @internal */
export declare function isStringDoubleQuoted(str: StringLiteralLike, sourceFile: SourceFile): boolean;
/** @internal */
export declare function isAssignmentDeclaration(decl: Declaration): boolean;
/**
 * Get the initializer, taking into account defaulted Javascript initializers
 *
 * @internal
 */
export declare function getEffectiveInitializer(node: HasExpressionInitializer): Expression | undefined;
/**
 * Get the declaration initializer when it is container-like (See getExpandoInitializer).
 *
 * @internal
 */
export declare function getDeclaredExpandoInitializer(node: HasExpressionInitializer): Expression | undefined;
/**
 * Get the assignment 'initializer' -- the righthand side-- when the initializer is container-like (See getExpandoInitializer).
 * We treat the right hand side of assignments with container-like initializers as declarations.
 *
 * @internal
 */
export declare function getAssignedExpandoInitializer(node: Node | undefined): Expression | undefined;
/**
 * Recognized expando initializers are:
 * 1. (function() {})() -- IIFEs
 * 2. function() { } -- Function expressions
 * 3. class { } -- Class expressions
 * 4. {} -- Empty object literals
 * 5. { ... } -- Non-empty object literals, when used to initialize a prototype, like `C.prototype = { m() { } }`
 *
 * This function returns the provided initializer, or undefined if it is not valid.
 *
 * @internal
 */
export declare function getExpandoInitializer(initializer: Node, isPrototypeAssignment: boolean): Expression | undefined;
/** @internal */
export declare function isDefaultedExpandoInitializer(node: BinaryExpression): boolean | undefined;
/**
 * Given an expando initializer, return its declaration name, or the left-hand side of the assignment if it's part of an assignment declaration.
 *
 * @internal
 */
export declare function getNameOfExpando(node: Declaration): DeclarationName | undefined;
/**
 * Is the 'declared' name the same as the one in the initializer?
 * @return true for identical entity names, as well as ones where the initializer is prefixed with
 * 'window', 'self' or 'global'. For example:
 *
 * var my = my || {}
 * var min = window.min || {}
 * my.app = self.my.app || class { }
 *
 * @internal
 */
export declare function isSameEntityName(name: Expression, initializer: Expression): boolean;
/** @internal */
export declare function getRightMostAssignedExpression(node: Expression): Expression;
/** @internal */
export declare function isExportsIdentifier(node: Node): boolean;
/** @internal */
export declare function isModuleIdentifier(node: Node): boolean;
/** @internal */
export declare function isModuleExportsAccessExpression(node: Node): node is LiteralLikeElementAccessExpression & {
    expression: Identifier;
};
/** @internal */
export declare function getAssignmentDeclarationKind(expr: BinaryExpression | CallExpression): AssignmentDeclarationKind;
/** @internal */
export declare function isBindableObjectDefinePropertyCall(expr: CallExpression): expr is BindableObjectDefinePropertyCall;
/**
 * x.y OR x[0]
 *
 * @internal
 */
export declare function isLiteralLikeAccess(node: Node): node is LiteralLikeElementAccessExpression | PropertyAccessExpression;
/**
 * x[0] OR x['a'] OR x[Symbol.y]
 *
 * @internal
 */
export declare function isLiteralLikeElementAccess(node: Node): node is LiteralLikeElementAccessExpression;
/**
 * Any series of property and element accesses.
 *
 * @internal
 */
export declare function isBindableStaticAccessExpression(node: Node, excludeThisKeyword?: boolean): node is BindableStaticAccessExpression;
/**
 * Any series of property and element accesses, ending in a literal element access
 *
 * @internal
 */
export declare function isBindableStaticElementAccessExpression(node: Node, excludeThisKeyword?: boolean): node is BindableStaticElementAccessExpression;
/** @internal */
export declare function isBindableStaticNameExpression(node: Node, excludeThisKeyword?: boolean): node is BindableStaticNameExpression;
/** @internal */
export declare function getNameOrArgument(expr: PropertyAccessExpression | LiteralLikeElementAccessExpression): MemberName | (Expression & (NumericLiteral | StringLiteralLike));
/**
 * Does not handle signed numeric names like `a[+0]` - handling those would require handling prefix unary expressions
 * throughout late binding handling as well, which is awkward (but ultimately probably doable if there is demand)
 *
 * @internal
 */
export declare function getElementOrPropertyAccessArgumentExpressionOrName(node: AccessExpression): Identifier | PrivateIdentifier | StringLiteralLike | NumericLiteral | ElementAccessExpression | undefined;
/** @internal */
export declare function getElementOrPropertyAccessName(node: LiteralLikeElementAccessExpression | PropertyAccessExpression): __String;
/** @internal */
export declare function getElementOrPropertyAccessName(node: AccessExpression): __String | undefined;
/** @internal */
export declare function getAssignmentDeclarationPropertyAccessKind(lhs: AccessExpression): AssignmentDeclarationKind;
/** @internal */
export declare function getInitializerOfBinaryExpression(expr: BinaryExpression): Expression;
/** @internal */
export interface PrototypePropertyAssignment extends AssignmentExpression<EqualsToken> {
    _prototypePropertyAssignmentBrand: any;
    readonly left: AccessExpression;
}
/** @internal */
export declare function isPrototypePropertyAssignment(node: Node): node is PrototypePropertyAssignment;
/** @internal */
export declare function isSpecialPropertyDeclaration(expr: PropertyAccessExpression | ElementAccessExpression): expr is PropertyAccessExpression | LiteralLikeElementAccessExpression;
/** @internal */
export declare function setValueDeclaration(symbol: Symbol, node: Declaration): void;
/** @internal */
export declare function isFunctionSymbol(symbol: Symbol | undefined): boolean | undefined;
/** @internal */
export declare function tryGetModuleSpecifierFromDeclaration(node: AnyImportOrBareOrAccessedRequire | AliasDeclarationNode): StringLiteralLike | undefined;
/** @internal */
export declare function importFromModuleSpecifier(node: StringLiteralLike): AnyValidImportOrReExport;
/** @internal */
export declare function tryGetImportFromModuleSpecifier(node: StringLiteralLike): AnyValidImportOrReExport | undefined;
/** @internal */
export declare function getExternalModuleName(node: AnyImportOrReExport | ImportTypeNode | ImportCall | ModuleDeclaration): Expression | undefined;
/** @internal */
export declare function getNamespaceDeclarationNode(node: ImportDeclaration | ImportEqualsDeclaration | ExportDeclaration): ImportEqualsDeclaration | NamespaceImport | NamespaceExport | undefined;
/** @internal */
export declare function isDefaultImport(node: ImportDeclaration | ImportEqualsDeclaration | ExportDeclaration): boolean;
/** @internal */
export declare function forEachImportClauseDeclaration<T>(node: ImportClause, action: (declaration: ImportClause | NamespaceImport | ImportSpecifier) => T | undefined): T | undefined;
/** @internal */
export declare function hasQuestionToken(node: Node): boolean;
/** @internal */
export declare function isJSDocConstructSignature(node: Node): boolean;
/** @internal */
export declare function isJSDocTypeAlias(node: Node): node is JSDocTypedefTag | JSDocCallbackTag | JSDocEnumTag;
/** @internal */
export declare function isTypeAlias(node: Node): node is JSDocTypedefTag | JSDocCallbackTag | JSDocEnumTag | TypeAliasDeclaration;
/** @internal */
export declare function getSingleInitializerOfVariableStatementOrPropertyDeclaration(node: Node): Expression | undefined;
/** @internal */
export declare function getSingleVariableOfVariableStatement(node: Node): VariableDeclaration | undefined;
/** @internal */
export declare function canHaveFlowNode(node: Node): node is HasFlowNode;
/** @internal */
export declare function canHaveJSDoc(node: Node): node is HasJSDoc;
/**
 * This function checks multiple locations for JSDoc comments that apply to a host node.
 * At each location, the whole comment may apply to the node, or only a specific tag in
 * the comment. In the first case, location adds the entire {@link JSDoc} object. In the
 * second case, it adds the applicable {@link JSDocTag}.
 *
 * For example, a JSDoc comment before a parameter adds the entire {@link JSDoc}. But a
 * `@param` tag on the parent function only adds the {@link JSDocTag} for the `@param`.
 *
 * ```ts
 * /** JSDoc will be returned for `a` *\/
 * const a = 0
 * /**
 *  * Entire JSDoc will be returned for `b`
 *  * @param c JSDocTag will be returned for `c`
 *  *\/
 * function b(/** JSDoc will be returned for `c` *\/ c) {}
 * ```
 */
export declare function getJSDocCommentsAndTags(hostNode: Node): readonly (JSDoc | JSDocTag)[];
/** @internal separate signature so that stripInternal can remove noCache from the public API */
export declare function getJSDocCommentsAndTags(hostNode: Node, noCache?: boolean): readonly (JSDoc | JSDocTag)[];
/** @internal */
export declare function getNextJSDocCommentLocation(node: Node): Node | undefined;
/**
 * Does the opposite of `getJSDocParameterTags`: given a JSDoc parameter, finds the parameter corresponding to it.
 *
 * @internal
 */
export declare function getParameterSymbolFromJSDoc(node: JSDocParameterTag): Symbol | undefined;
/** @internal */
export declare function getEffectiveContainerForJSDocTemplateTag(node: JSDocTemplateTag): SignatureDeclaration | JSDocCallbackTag | JSDocEnumTag | JSDocTypedefTag | undefined;
/** @internal */
export declare function getHostSignatureFromJSDoc(node: Node): SignatureDeclaration | undefined;
/** @internal */
export declare function getEffectiveJSDocHost(node: Node): Node | undefined;
/**
 * Use getEffectiveJSDocHost if you additionally need to look for jsdoc on parent nodes, like assignments.
 *
 * @internal
 */
export declare function getJSDocHost(node: Node): HasJSDoc | undefined;
/** @internal */
export declare function getJSDocRoot(node: Node): JSDoc | undefined;
/** @internal */
export declare function getTypeParameterFromJsDoc(node: TypeParameterDeclaration & {
    parent: JSDocTemplateTag;
}): TypeParameterDeclaration | undefined;
/** @internal */
export declare function hasTypeArguments(node: Node): node is HasTypeArguments;
/** @internal */
export declare const enum AssignmentKind {
    None = 0,
    Definite = 1,
    Compound = 2
}
/** @internal */
export declare function getAssignmentTargetKind(node: Node): AssignmentKind;
/** @internal */
export declare function isAssignmentTarget(node: Node): boolean;
/** @internal */
export type NodeWithPossibleHoistedDeclaration = Block | VariableStatement | WithStatement | IfStatement | SwitchStatement | CaseBlock | CaseClause | DefaultClause | LabeledStatement | ForStatement | ForInStatement | ForOfStatement | DoStatement | WhileStatement | TryStatement | CatchClause;
/**
 * Indicates whether a node could contain a `var` VariableDeclarationList that contributes to
 * the same `var` declaration scope as the node's parent.
 *
 * @internal
 */
export declare function isNodeWithPossibleHoistedDeclaration(node: Node): node is NodeWithPossibleHoistedDeclaration;
/** @internal */
export type ValueSignatureDeclaration = FunctionDeclaration | MethodDeclaration | ConstructorDeclaration | AccessorDeclaration | FunctionExpression | ArrowFunction;
/** @internal */
export declare function isValueSignatureDeclaration(node: Node): node is ValueSignatureDeclaration;
/** @internal */
export declare function walkUpParenthesizedTypes(node: Node): Node;
/** @internal */
export declare function walkUpParenthesizedExpressions(node: Node): Node;
/**
 * Walks up parenthesized types.
 * It returns both the outermost parenthesized type and its parent.
 * If given node is not a parenthesiezd type, undefined is return as the former.
 *
 * @internal
 */
export declare function walkUpParenthesizedTypesAndGetParentAndChild(node: Node): [ParenthesizedTypeNode | undefined, Node];
/** @internal */
export declare function skipTypeParentheses(node: TypeNode): TypeNode;
/** @internal */
export declare function skipParentheses(node: Expression, excludeJSDocTypeAssertions?: boolean): Expression;
/** @internal */
export declare function skipParentheses(node: Node, excludeJSDocTypeAssertions?: boolean): Node;
/** @internal */
export declare function isDeleteTarget(node: Node): boolean;
/** @internal */
export declare function isNodeDescendantOf(node: Node, ancestor: Node | undefined): boolean;
/** @internal */
export declare function isDeclarationName(name: Node): boolean;
/** @internal */
export declare function getDeclarationFromName(name: Node): Declaration | undefined;
/** @internal */
export declare function isLiteralComputedPropertyDeclarationName(node: Node): boolean;
/** @internal */
export declare function isIdentifierName(node: Identifier): boolean;
/** @internal */
export declare function isAliasSymbolDeclaration(node: Node): boolean;
/** @internal */
export declare function getAliasDeclarationFromName(node: EntityName): Declaration | undefined;
/** @internal */
export declare function isAliasableExpression(e: Expression): boolean;
/** @internal */
export declare function exportAssignmentIsAlias(node: ExportAssignment | BinaryExpression): boolean;
/** @internal */
export declare function getExportAssignmentExpression(node: ExportAssignment | BinaryExpression): Expression;
/** @internal */
export declare function getPropertyAssignmentAliasLikeExpression(node: PropertyAssignment | ShorthandPropertyAssignment | PropertyAccessExpression): Expression;
/** @internal */
export declare function getEffectiveBaseTypeNode(node: ClassLikeDeclaration | InterfaceDeclaration): ExpressionWithTypeArguments | undefined;
/** @internal */
export declare function getClassExtendsHeritageElement(node: ClassLikeDeclaration | InterfaceDeclaration): ExpressionWithTypeArguments | undefined;
/** @internal */
export declare function getEffectiveImplementsTypeNodes(node: ClassLikeDeclaration): undefined | readonly ExpressionWithTypeArguments[];
/**
 * Returns the node in an `extends` or `implements` clause of a class or interface.
 *
 * @internal
 */
export declare function getAllSuperTypeNodes(node: Node): readonly TypeNode[];
/** @internal */
export declare function getInterfaceBaseTypeNodes(node: InterfaceDeclaration): NodeArray<ExpressionWithTypeArguments> | undefined;
/** @internal */
export declare function getHeritageClause(clauses: NodeArray<HeritageClause> | undefined, kind: SyntaxKind): HeritageClause | undefined;
/** @internal */
export declare function getAncestor(node: Node | undefined, kind: SyntaxKind): Node | undefined;
/** @internal */
export declare function isKeyword(token: SyntaxKind): token is KeywordSyntaxKind;
/** @internal */
export declare function isPunctuation(token: SyntaxKind): token is PunctuationSyntaxKind;
/** @internal */
export declare function isKeywordOrPunctuation(token: SyntaxKind): token is PunctuationOrKeywordSyntaxKind;
/** @internal */
export declare function isContextualKeyword(token: SyntaxKind): boolean;
/** @internal */
export declare function isNonContextualKeyword(token: SyntaxKind): boolean;
/** @internal */
export declare function isFutureReservedKeyword(token: SyntaxKind): boolean;
/** @internal */
export declare function isStringANonContextualKeyword(name: string): boolean;
/** @internal */
export declare function isStringAKeyword(name: string): boolean;
/** @internal */
export declare function isIdentifierANonContextualKeyword(node: Identifier): boolean;
/** @internal */
export declare function isTrivia(token: SyntaxKind): token is TriviaSyntaxKind;
/** @internal */
export declare const enum FunctionFlags {
    Normal = 0,
    Generator = 1,
    Async = 2,
    Invalid = 4,
    AsyncGenerator = 3
}
/** @internal */
export declare function getFunctionFlags(node: SignatureDeclaration | undefined): FunctionFlags;
/** @internal */
export declare function isAsyncFunction(node: Node): boolean;
/** @internal */
export declare function isStringOrNumericLiteralLike(node: Node): node is StringLiteralLike | NumericLiteral;
/** @internal */
export declare function isSignedNumericLiteral(node: Node): node is PrefixUnaryExpression & {
    operand: NumericLiteral;
};
/**
 * A declaration has a dynamic name if all of the following are true:
 *   1. The declaration has a computed property name.
 *   2. The computed name is *not* expressed as a StringLiteral.
 *   3. The computed name is *not* expressed as a NumericLiteral.
 *   4. The computed name is *not* expressed as a PlusToken or MinusToken
 *      immediately followed by a NumericLiteral.
 *
 * @internal
 */
export declare function hasDynamicName(declaration: Declaration): declaration is DynamicNamedDeclaration | DynamicNamedBinaryExpression;
/** @internal */
export declare function isDynamicName(name: DeclarationName): boolean;
/** @internal */
export declare function getPropertyNameForPropertyNameNode(name: PropertyName | JsxAttributeName): __String | undefined;
/** @internal */
export declare function isPropertyNameLiteral(node: Node): node is PropertyNameLiteral;
/** @internal */
export declare function getTextOfIdentifierOrLiteral(node: PropertyNameLiteral | PrivateIdentifier): string;
/** @internal */
export declare function getEscapedTextOfIdentifierOrLiteral(node: PropertyNameLiteral): __String;
/** @internal */
export declare function getPropertyNameForUniqueESSymbol(symbol: Symbol): __String;
/** @internal */
export declare function getSymbolNameForPrivateIdentifier(containingClassSymbol: Symbol, description: __String): __String;
/** @internal */
export declare function isKnownSymbol(symbol: Symbol): boolean;
/** @internal */
export declare function isPrivateIdentifierSymbol(symbol: Symbol): boolean;
/**
 * Includes the word "Symbol" with unicode escapes
 *
 * @internal
 */
export declare function isESSymbolIdentifier(node: Node): boolean;
/**
 * Indicates whether a property name is the special `__proto__` property.
 * Per the ECMA-262 spec, this only matters for property assignments whose name is
 * the Identifier `__proto__`, or the string literal `"__proto__"`, but not for
 * computed property names.
 *
 * @internal
 */
export declare function isProtoSetter(node: PropertyName): boolean;
/** @internal */
export type AnonymousFunctionDefinition = ClassExpression & {
    readonly name?: undefined;
} | FunctionExpression & {
    readonly name?: undefined;
} | ArrowFunction;
/**
 * Indicates whether an expression is an anonymous function definition.
 *
 * @see https://tc39.es/ecma262/#sec-isanonymousfunctiondefinition
 * @internal
 */
export declare function isAnonymousFunctionDefinition(node: Expression, cb?: (node: AnonymousFunctionDefinition) => boolean): node is WrappedExpression<AnonymousFunctionDefinition>;
/** @internal */
export type NamedEvaluationSource = PropertyAssignment & {
    readonly name: Identifier;
} | ShorthandPropertyAssignment & {
    readonly objectAssignmentInitializer: Expression;
} | VariableDeclaration & {
    readonly name: Identifier;
    readonly initializer: Expression;
} | ParameterDeclaration & {
    readonly name: Identifier;
    readonly initializer: Expression;
    readonly dotDotDotToken: undefined;
} | BindingElement & {
    readonly name: Identifier;
    readonly initializer: Expression;
    readonly dotDotDotToken: undefined;
} | PropertyDeclaration & {
    readonly initializer: Expression;
} | AssignmentExpression<EqualsToken | AmpersandAmpersandEqualsToken | BarBarEqualsToken | QuestionQuestionEqualsToken> & {
    readonly left: Identifier;
} | ExportAssignment;
/**
 * Indicates whether a node is a potential source of an assigned name for a class, function, or arrow function.
 *
 * @internal
 */
export declare function isNamedEvaluationSource(node: Node): node is NamedEvaluationSource;
/** @internal */
export type NamedEvaluation = PropertyAssignment & {
    readonly name: Identifier;
    readonly initializer: WrappedExpression<AnonymousFunctionDefinition>;
} | ShorthandPropertyAssignment & {
    readonly objectAssignmentInitializer: WrappedExpression<AnonymousFunctionDefinition>;
} | VariableDeclaration & {
    readonly name: Identifier;
    readonly initializer: WrappedExpression<AnonymousFunctionDefinition>;
} | ParameterDeclaration & {
    readonly name: Identifier;
    readonly dotDotDotToken: undefined;
    readonly initializer: WrappedExpression<AnonymousFunctionDefinition>;
} | BindingElement & {
    readonly name: Identifier;
    readonly dotDotDotToken: undefined;
    readonly initializer: WrappedExpression<AnonymousFunctionDefinition>;
} | PropertyDeclaration & {
    readonly initializer: WrappedExpression<AnonymousFunctionDefinition>;
} | AssignmentExpression<EqualsToken | AmpersandAmpersandEqualsToken | BarBarEqualsToken | QuestionQuestionEqualsToken> & {
    readonly left: Identifier;
    readonly right: WrappedExpression<AnonymousFunctionDefinition>;
} | ExportAssignment & {
    readonly expression: WrappedExpression<AnonymousFunctionDefinition>;
};
/** @internal */
export declare function isNamedEvaluation(node: Node, cb?: (node: AnonymousFunctionDefinition) => boolean): node is NamedEvaluation;
/** @internal */
export declare function isPushOrUnshiftIdentifier(node: Identifier): boolean;
/**
 * This function returns true if the this node's root declaration is a parameter.
 * For example, passing a `ParameterDeclaration` will return true, as will passing a
 * binding element that is a child of a `ParameterDeclaration`.
 *
 * If you are looking to test that a `Node` is a `ParameterDeclaration`, use `isParameter`.
 *
 * @internal
 */
export declare function isParameterDeclaration(node: Declaration): boolean;
/** @internal */
export declare function getRootDeclaration(node: Node): Node;
/** @internal */
export declare function nodeStartsNewLexicalEnvironment(node: Node): boolean;
/** @internal */
export declare function nodeIsSynthesized(range: TextRange): boolean;
/** @internal */
export declare function getOriginalSourceFile(sourceFile: SourceFile): SourceFile;
/** @internal */
export declare const enum Associativity {
    Left = 0,
    Right = 1
}
/** @internal */
export declare function getExpressionAssociativity(expression: Expression): Associativity;
/** @internal */
export declare function getOperatorAssociativity(kind: SyntaxKind, operator: SyntaxKind, hasArguments?: boolean): Associativity;
/** @internal */
export declare function getExpressionPrecedence(expression: Expression): OperatorPrecedence;
/** @internal */
export declare function getOperator(expression: Expression): SyntaxKind;
/** @internal */
export declare const enum OperatorPrecedence {
    Comma = 0,
    Spread = 1,
    Yield = 2,
    Assignment = 3,
    Conditional = 4,
    Coalesce = 4,
    LogicalOR = 5,
    LogicalAND = 6,
    BitwiseOR = 7,
    BitwiseXOR = 8,
    BitwiseAND = 9,
    Equality = 10,
    Relational = 11,
    Shift = 12,
    Additive = 13,
    Multiplicative = 14,
    Exponentiation = 15,
    Unary = 16,
    Update = 17,
    LeftHandSide = 18,
    Member = 19,
    Primary = 20,
    Highest = 20,
    Lowest = 0,
    Invalid = -1
}
/** @internal */
export declare function getOperatorPrecedence(nodeKind: SyntaxKind, operatorKind: SyntaxKind, hasArguments?: boolean): OperatorPrecedence;
/** @internal */
export declare function getBinaryOperatorPrecedence(kind: SyntaxKind): OperatorPrecedence;
/** @internal */
export declare function getSemanticJsxChildren(children: readonly JsxChild[]): readonly JsxChild[];
/** @internal */
export declare function createDiagnosticCollection(): DiagnosticCollection;
/** @internal */
export declare function hasInvalidEscape(template: TemplateLiteral): boolean;
/**
 * Based heavily on the abstract 'Quote'/'QuoteJSONString' operation from ECMA-262 (24.3.2.2),
 * but augmented for a few select characters (e.g. lineSeparator, paragraphSeparator, nextLine)
 * Note that this doesn't actually wrap the input in double quotes.
 *
 * @internal
 */
export declare function escapeString(s: string, quoteChar?: CharacterCodes.doubleQuote | CharacterCodes.singleQuote | CharacterCodes.backtick): string;
/** @internal */
export declare function escapeNonAsciiString(s: string, quoteChar?: CharacterCodes.doubleQuote | CharacterCodes.singleQuote | CharacterCodes.backtick): string;
/** @internal */
export declare function escapeJsxAttributeString(s: string, quoteChar?: CharacterCodes.doubleQuote | CharacterCodes.singleQuote): string;
/**
 * Strip off existed surrounding single quotes, double quotes, or backticks from a given string
 *
 * @return non-quoted string
 *
 * @internal
 */
export declare function stripQuotes(name: string): string;
/** @internal */
export declare function isIntrinsicJsxName(name: __String | string): boolean;
/** @internal */
export declare function getIndentString(level: number): string;
/** @internal */
export declare function getIndentSize(): number;
/** @internal */
export declare function isNightly(): boolean;
/** @internal */
export declare function createTextWriter(newLine: string): EmitTextWriter;
/** @internal */
export declare function getTrailingSemicolonDeferringWriter(writer: EmitTextWriter): EmitTextWriter;
/** @internal */
export declare function hostUsesCaseSensitiveFileNames(host: {
    useCaseSensitiveFileNames?(): boolean;
}): boolean;
/** @internal */
export declare function hostGetCanonicalFileName(host: {
    useCaseSensitiveFileNames?(): boolean;
}): GetCanonicalFileName;
/** @internal */
export interface ResolveModuleNameResolutionHost {
    getCanonicalFileName(p: string): string;
    getCommonSourceDirectory(): string;
    getCurrentDirectory(): string;
}
/** @internal */
export declare function getResolvedExternalModuleName(host: ResolveModuleNameResolutionHost, file: SourceFile, referenceFile?: SourceFile): string;
/** @internal */
export declare function getExternalModuleNameFromDeclaration(host: ResolveModuleNameResolutionHost, resolver: EmitResolver, declaration: ImportEqualsDeclaration | ImportDeclaration | ExportDeclaration | ModuleDeclaration | ImportTypeNode): string | undefined;
/**
 * Resolves a local path to a path which is absolute to the base of the emit
 *
 * @internal
 */
export declare function getExternalModuleNameFromPath(host: ResolveModuleNameResolutionHost, fileName: string, referencePath?: string): string;
/** @internal */
export declare function getOwnEmitOutputFilePath(fileName: string, host: EmitHost, extension: string): string;
/** @internal */
export declare function getDeclarationEmitOutputFilePath(fileName: string, host: EmitHost): string;
/** @internal */
export declare function getDeclarationEmitOutputFilePathWorker(fileName: string, options: CompilerOptions, currentDirectory: string, commonSourceDirectory: string, getCanonicalFileName: GetCanonicalFileName): string;
/** @internal */
export declare function getDeclarationEmitExtensionForPath(path: string): Extension.Dts | Extension.Dmts | Extension.Dcts | ".d.json.ts";
/**
 * This function is an inverse of `getDeclarationEmitExtensionForPath`.
 *
 * @internal
 */
export declare function getPossibleOriginalInputExtensionForExtension(path: string): Extension[];
/** @internal */
export declare function outFile(options: CompilerOptions): string | undefined;
/**
 * Returns 'undefined' if and only if 'options.paths' is undefined.
 *
 * @internal
 */
export declare function getPathsBasePath(options: CompilerOptions, host: {
    getCurrentDirectory?(): string;
}): string | undefined;
/** @internal */
export interface EmitFileNames {
    jsFilePath?: string | undefined;
    sourceMapFilePath?: string | undefined;
    declarationFilePath?: string | undefined;
    declarationMapPath?: string | undefined;
    buildInfoPath?: string | undefined;
}
/**
 * Gets the source files that are expected to have an emit output.
 *
 * Originally part of `forEachExpectedEmitFile`, this functionality was extracted to support
 * transformations.
 *
 * @param host An EmitHost.
 * @param targetSourceFile An optional target source file to emit.
 *
 * @internal
 */
export declare function getSourceFilesToEmit(host: EmitHost, targetSourceFile?: SourceFile, forceDtsEmit?: boolean): readonly SourceFile[];
/**
 * Don't call this for `--outFile`, just for `--outDir` or plain emit. `--outFile` needs additional checks.
 *
 * @internal
 */
export declare function sourceFileMayBeEmitted(sourceFile: SourceFile, host: SourceFileMayBeEmittedHost, forceDtsEmit?: boolean): boolean;
/** @internal */
export declare function getSourceFilePathInNewDir(fileName: string, host: EmitHost, newDirPath: string): string;
/** @internal */
export declare function getSourceFilePathInNewDirWorker(fileName: string, newDirPath: string, currentDirectory: string, commonSourceDirectory: string, getCanonicalFileName: GetCanonicalFileName): string;
/** @internal */
export declare function writeFile(host: {
    writeFile: WriteFileCallback;
}, diagnostics: DiagnosticCollection, fileName: string, text: string, writeByteOrderMark: boolean, sourceFiles?: readonly SourceFile[], data?: WriteFileCallbackData): void;
/** @internal */
export declare function writeFileEnsuringDirectories(path: string, data: string, writeByteOrderMark: boolean, writeFile: (path: string, data: string, writeByteOrderMark: boolean) => void, createDirectory: (path: string) => void, directoryExists: (path: string) => boolean): void;
/** @internal */
export declare function getLineOfLocalPosition(sourceFile: SourceFile, pos: number): number;
/** @internal */
export declare function getLineOfLocalPositionFromLineMap(lineMap: readonly number[], pos: number): number;
/** @internal */
export declare function getFirstConstructorWithBody(node: ClassLikeDeclaration): ConstructorDeclaration & {
    body: FunctionBody;
} | undefined;
/** @internal */
export declare function getSetAccessorValueParameter(accessor: SetAccessorDeclaration): ParameterDeclaration | undefined;
/**
 * Get the type annotation for the value parameter.
 *
 * @internal
 */
export declare function getSetAccessorTypeAnnotationNode(accessor: SetAccessorDeclaration): TypeNode | undefined;
/** @internal */
export declare function getThisParameter(signature: SignatureDeclaration | JSDocSignature): ParameterDeclaration | undefined;
/** @internal */
export declare function parameterIsThisKeyword(parameter: ParameterDeclaration): boolean;
/** @internal */
export declare function isThisIdentifier(node: Node | undefined): boolean;
/** @internal */
export declare function isThisInTypeQuery(node: Node): boolean;
/** @internal */
export declare function identifierIsThisKeyword(id: Identifier): boolean;
/** @internal */
export declare function getAllAccessorDeclarations(declarations: readonly Declaration[], accessor: AccessorDeclaration): AllAccessorDeclarations;
/**
 * Gets the effective type annotation of a variable, parameter, or property. If the node was
 * parsed in a JavaScript file, gets the type annotation from JSDoc.  Also gets the type of
 * functions only the JSDoc case.
 *
 * @internal
 */
export declare function getEffectiveTypeAnnotationNode(node: Node): TypeNode | undefined;
/** @internal */
export declare function getTypeAnnotationNode(node: Node): TypeNode | undefined;
/**
 * Gets the effective return type annotation of a signature. If the node was parsed in a
 * JavaScript file, gets the return type annotation from JSDoc.
 *
 * @internal
 */
export declare function getEffectiveReturnTypeNode(node: SignatureDeclaration | JSDocSignature): TypeNode | undefined;
/** @internal */
export declare function getJSDocTypeParameterDeclarations(node: DeclarationWithTypeParameters): readonly TypeParameterDeclaration[];
/**
 * Gets the effective type annotation of the value parameter of a set accessor. If the node
 * was parsed in a JavaScript file, gets the type annotation from JSDoc.
 *
 * @internal
 */
export declare function getEffectiveSetAccessorTypeAnnotationNode(node: SetAccessorDeclaration): TypeNode | undefined;
/** @internal */
export declare function emitNewLineBeforeLeadingComments(lineMap: readonly number[], writer: EmitTextWriter, node: TextRange, leadingComments: readonly CommentRange[] | undefined): void;
/** @internal */
export declare function emitNewLineBeforeLeadingCommentsOfPosition(lineMap: readonly number[], writer: EmitTextWriter, pos: number, leadingComments: readonly CommentRange[] | undefined): void;
/** @internal */
export declare function emitNewLineBeforeLeadingCommentOfPosition(lineMap: readonly number[], writer: EmitTextWriter, pos: number, commentPos: number): void;
/** @internal */
export declare function emitComments(text: string, lineMap: readonly number[], writer: EmitTextWriter, comments: readonly CommentRange[] | undefined, leadingSeparator: boolean, trailingSeparator: boolean, newLine: string, writeComment: (text: string, lineMap: readonly number[], writer: EmitTextWriter, commentPos: number, commentEnd: number, newLine: string) => void): void;
/**
 * Detached comment is a comment at the top of file or function body that is separated from
 * the next statement by space.
 *
 * @internal
 */
export declare function emitDetachedComments(text: string, lineMap: readonly number[], writer: EmitTextWriter, writeComment: (text: string, lineMap: readonly number[], writer: EmitTextWriter, commentPos: number, commentEnd: number, newLine: string) => void, node: TextRange, newLine: string, removeComments: boolean): {
    nodePos: number;
    detachedCommentEndPos: number;
} | undefined;
/** @internal */
export declare function writeCommentRange(text: string, lineMap: readonly number[], writer: EmitTextWriter, commentPos: number, commentEnd: number, newLine: string): void;
/** @internal */
export declare function hasEffectiveModifiers(node: Node): boolean;
/** @internal */
export declare function hasSyntacticModifiers(node: Node): boolean;
/** @internal */
export declare function hasEffectiveModifier(node: Node, flags: ModifierFlags): boolean;
/** @internal */
export declare function hasSyntacticModifier(node: Node, flags: ModifierFlags): boolean;
/** @internal */
export declare function isStatic(node: Node): boolean;
/** @internal */
export declare function hasStaticModifier(node: Node): boolean;
/** @internal */
export declare function hasOverrideModifier(node: Node): boolean;
/** @internal */
export declare function hasAbstractModifier(node: Node): boolean;
/** @internal */
export declare function hasAmbientModifier(node: Node): boolean;
/** @internal */
export declare function hasAccessorModifier(node: Node): boolean;
/** @internal */
export declare function hasEffectiveReadonlyModifier(node: Node): boolean;
/** @internal */
export declare function hasDecorators(node: Node): boolean;
/** @internal */
export declare function getSelectedEffectiveModifierFlags(node: Node, flags: ModifierFlags): ModifierFlags;
/** @internal */
export declare function getSelectedSyntacticModifierFlags(node: Node, flags: ModifierFlags): ModifierFlags;
/**
 * Gets the effective ModifierFlags for the provided node, including JSDoc modifiers. The modifiers will be cached on the node to improve performance.
 *
 * NOTE: This function may use `parent` pointers.
 *
 * @internal
 */
export declare function getEffectiveModifierFlags(node: Node): ModifierFlags;
/** @internal */
export declare function getEffectiveModifierFlagsAlwaysIncludeJSDoc(node: Node): ModifierFlags;
/**
 * Gets the ModifierFlags for syntactic modifiers on the provided node. The modifiers will be cached on the node to improve performance.
 *
 * NOTE: This function does not use `parent` pointers and will not include modifiers from JSDoc.
 *
 * @internal
 */
export declare function getSyntacticModifierFlags(node: Node): ModifierFlags;
/**
 * Gets the effective ModifierFlags for the provided node, including JSDoc modifiers. The modifier flags cache on the node is ignored.
 *
 * NOTE: This function may use `parent` pointers.
 *
 * @internal
 */
export declare function getEffectiveModifierFlagsNoCache(node: Node): ModifierFlags;
/**
 * Gets the ModifierFlags for syntactic modifiers on the provided node. The modifier flags cache on the node is ignored.
 *
 * NOTE: This function does not use `parent` pointers and will not include modifiers from JSDoc.
 *
 * @internal
 */
export declare function getSyntacticModifierFlagsNoCache(node: Node): ModifierFlags;
/** @internal */
export declare function modifiersToFlags(modifiers: readonly ModifierLike[] | undefined): ModifierFlags;
/** @internal */
export declare function modifierToFlag(token: SyntaxKind): ModifierFlags;
/** @internal */
export declare function isLogicalOperator(token: SyntaxKind): boolean;
/** @internal */
export declare function isLogicalOrCoalescingAssignmentOperator(token: SyntaxKind): token is LogicalOrCoalescingAssignmentOperator;
/** @internal */
export declare function isLogicalOrCoalescingAssignmentExpression(expr: Node): expr is AssignmentExpression<Token<LogicalOrCoalescingAssignmentOperator>>;
/** @internal */
export declare function isLogicalOrCoalescingBinaryOperator(token: SyntaxKind): token is LogicalOperator | SyntaxKind.QuestionQuestionToken;
/** @internal */
export declare function isLogicalOrCoalescingBinaryExpression(expr: Node): expr is BinaryExpression;
/** @internal */
export declare function isAssignmentOperator(token: SyntaxKind): boolean;
/**
 * Get `C` given `N` if `N` is in the position `class C extends N` where `N` is an ExpressionWithTypeArguments.
 *
 * @internal
 */
export declare function tryGetClassExtendingExpressionWithTypeArguments(node: Node): ClassLikeDeclaration | undefined;
/** @internal */
export interface ClassImplementingOrExtendingExpressionWithTypeArguments {
    readonly class: ClassLikeDeclaration;
    readonly isImplements: boolean;
}
/** @internal */
export declare function tryGetClassImplementingOrExtendingExpressionWithTypeArguments(node: Node): ClassImplementingOrExtendingExpressionWithTypeArguments | undefined;
/** @internal */
export declare function isAssignmentExpression(node: Node, excludeCompoundAssignment: true): node is AssignmentExpression<EqualsToken>;
/** @internal */
export declare function isAssignmentExpression(node: Node, excludeCompoundAssignment?: false): node is AssignmentExpression<AssignmentOperatorToken>;
/** @internal */
export declare function isLeftHandSideOfAssignment(node: Node): boolean;
/** @internal */
export declare function isDestructuringAssignment(node: Node): node is DestructuringAssignment;
/** @internal */
export declare function isExpressionWithTypeArgumentsInClassExtendsClause(node: Node): node is ExpressionWithTypeArguments;
/** @internal */
export declare function isEntityNameExpression(node: Node): node is EntityNameExpression;
/** @internal */
export declare function getFirstIdentifier(node: EntityNameOrEntityNameExpression): Identifier;
/** @internal */
export declare function isDottedName(node: Expression): boolean;
/** @internal */
export declare function isPropertyAccessEntityNameExpression(node: Node): node is PropertyAccessEntityNameExpression;
/** @internal */
export declare function tryGetPropertyAccessOrIdentifierToString(expr: Expression | JsxTagNameExpression): string | undefined;
/** @internal */
export declare function isPrototypeAccess(node: Node): node is BindableStaticAccessExpression;
/** @internal */
export declare function isRightSideOfQualifiedNameOrPropertyAccess(node: Node): boolean;
/** @internal */
export declare function isRightSideOfAccessExpression(node: Node): boolean;
/** @internal */
export declare function isRightSideOfQualifiedNameOrPropertyAccessOrJSDocMemberName(node: Node): boolean;
/** @internal */
export declare function isEmptyObjectLiteral(expression: Node): boolean;
/** @internal */
export declare function isEmptyArrayLiteral(expression: Node): boolean;
/** @internal */
export declare function getLocalSymbolForExportDefault(symbol: Symbol): Symbol | undefined;
/**
 * Return ".ts", ".d.ts", or ".tsx", if that is the extension.
 *
 * @internal
 */
export declare function tryExtractTSExtension(fileName: string): string | undefined;
/**
 * Converts a string to a base-64 encoded ASCII string.
 *
 * @internal
 */
export declare function convertToBase64(input: string): string;
/** @internal */
export declare function base64encode(host: {
    base64encode?(input: string): string;
} | undefined, input: string): string;
/** @internal */
export declare function base64decode(host: {
    base64decode?(input: string): string;
} | undefined, input: string): string;
/** @internal */
export declare function readJsonOrUndefined(path: string, hostOrText: {
    readFile(fileName: string): string | undefined;
} | string): object | undefined;
/** @internal */
export declare function readJson(path: string, host: {
    readFile(fileName: string): string | undefined;
}): object;
/** @internal */
export declare function directoryProbablyExists(directoryName: string, host: {
    directoryExists?: (directoryName: string) => boolean;
}): boolean;
/** @internal */
export declare function getNewLineCharacter(options: CompilerOptions | PrinterOptions): string;
/**
 * Creates a new TextRange from the provided pos and end.
 *
 * @param pos The start position.
 * @param end The end position.
 *
 * @internal
 */
export declare function createRange(pos: number, end?: number): TextRange;
/**
 * Creates a new TextRange from a provided range with a new end position.
 *
 * @param range A TextRange.
 * @param end The new end position.
 *
 * @internal
 */
export declare function moveRangeEnd(range: TextRange, end: number): TextRange;
/**
 * Creates a new TextRange from a provided range with a new start position.
 *
 * @param range A TextRange.
 * @param pos The new Start position.
 *
 * @internal
 */
export declare function moveRangePos(range: TextRange, pos: number): TextRange;
/**
 * Moves the start position of a range past any decorators.
 *
 * @internal
 */
export declare function moveRangePastDecorators(node: Node): TextRange;
/**
 * Moves the start position of a range past any decorators or modifiers.
 *
 * @internal
 */
export declare function moveRangePastModifiers(node: Node): TextRange;
/**
 * Determines whether a TextRange has the same start and end positions.
 *
 * @param range A TextRange.
 *
 * @internal
 */
export declare function isCollapsedRange(range: TextRange): boolean;
/**
 * Creates a new TextRange for a token at the provides start position.
 *
 * @param pos The start position.
 * @param token The token.
 *
 * @internal
 */
export declare function createTokenRange(pos: number, token: SyntaxKind): TextRange;
/** @internal */
export declare function rangeIsOnSingleLine(range: TextRange, sourceFile: SourceFile): boolean;
/** @internal */
export declare function rangeStartPositionsAreOnSameLine(range1: TextRange, range2: TextRange, sourceFile: SourceFile): boolean;
/** @internal */
export declare function rangeEndPositionsAreOnSameLine(range1: TextRange, range2: TextRange, sourceFile: SourceFile): boolean;
/** @internal */
export declare function rangeStartIsOnSameLineAsRangeEnd(range1: TextRange, range2: TextRange, sourceFile: SourceFile): boolean;
/** @internal */
export declare function rangeEndIsOnSameLineAsRangeStart(range1: TextRange, range2: TextRange, sourceFile: SourceFile): boolean;
/** @internal */
export declare function getLinesBetweenRangeEndAndRangeStart(range1: TextRange, range2: TextRange, sourceFile: SourceFile, includeSecondRangeComments: boolean): number;
/** @internal */
export declare function getLinesBetweenRangeEndPositions(range1: TextRange, range2: TextRange, sourceFile: SourceFile): number;
/** @internal */
export declare function isNodeArrayMultiLine(list: NodeArray<Node>, sourceFile: SourceFile): boolean;
/** @internal */
export declare function positionsAreOnSameLine(pos1: number, pos2: number, sourceFile: SourceFile): boolean;
/** @internal */
export declare function getStartPositionOfRange(range: TextRange, sourceFile: SourceFile, includeComments: boolean): number;
/** @internal */
export declare function getLinesBetweenPositionAndPrecedingNonWhitespaceCharacter(pos: number, stopPos: number, sourceFile: SourceFile, includeComments?: boolean): number;
/** @internal */
export declare function getLinesBetweenPositionAndNextNonWhitespaceCharacter(pos: number, stopPos: number, sourceFile: SourceFile, includeComments?: boolean): number;
/**
 * Determines whether a name was originally the declaration name of an enum or namespace
 * declaration.
 *
 * @internal
 */
export declare function isDeclarationNameOfEnumOrNamespace(node: Identifier): boolean;
/** @internal */
export declare function getInitializedVariables(node: VariableDeclarationList): readonly InitializedVariableDeclaration[];
/** @internal */
export declare function isInitializedVariable(node: Node): node is InitializedVariableDeclaration;
/** @internal */
export declare function isWatchSet(options: CompilerOptions): boolean | undefined;
/** @internal */
export declare function closeFileWatcher(watcher: FileWatcher): void;
/** @internal */
export declare function getCheckFlags(symbol: Symbol): CheckFlags;
/** @internal */
export declare function getDeclarationModifierFlagsFromSymbol(s: Symbol, isWrite?: boolean): ModifierFlags;
/** @internal */
export declare function skipAlias(symbol: Symbol, checker: TypeChecker): Symbol;
/**
 * See comment on `declareModuleMember` in `binder.ts`.
 *
 * @internal
 */
export declare function getCombinedLocalAndExportSymbolFlags(symbol: Symbol): SymbolFlags;
/** @internal */
export declare function isWriteOnlyAccess(node: Node): boolean;
/** @internal */
export declare function isWriteAccess(node: Node): boolean;
/** @internal */
export declare function compareDataObjects(dst: any, src: any): boolean;
/**
 * clears already present map by calling onDeleteExistingValue callback before deleting that key/value
 *
 * @internal
 */
export declare function clearMap<K, T>(map: {
    forEach: Map<K, T>["forEach"];
    clear: Map<K, T>["clear"];
}, onDeleteValue: (valueInMap: T, key: K) => void): void;
/** @internal */
export interface MutateMapSkippingNewValuesOptions<K, T, U> {
    onDeleteValue(existingValue: T, key: K): void;
    /**
     * If present this is called with the key when there is value for that key both in new map as well as existing map provided
     * Caller can then decide to update or remove this key.
     * If the key is removed, caller will get callback of createNewValue for that key.
     * If this callback is not provided, the value of such keys is not updated.
     */
    onExistingValue?(existingValue: T, valueInNewMap: U, key: K): void;
}
/**
 * Mutates the map with newMap such that keys in map will be same as newMap.
 *
 * @internal
 */
export declare function mutateMapSkippingNewValues<K, T, U>(map: Map<K, T>, newMap: ReadonlyMap<K, U>, options: MutateMapSkippingNewValuesOptions<K, T, U>): void;
/** @internal */
export interface MutateMapOptions<K, T, U> extends MutateMapSkippingNewValuesOptions<K, T, U> {
    createNewValue(key: K, valueInNewMap: U): T;
}
/**
 * Mutates the map with newMap such that keys in map will be same as newMap.
 *
 * @internal
 */
export declare function mutateMap<K, T, U>(map: Map<K, T>, newMap: ReadonlyMap<K, U>, options: MutateMapOptions<K, T, U>): void;
/** @internal */
export declare function isAbstractConstructorSymbol(symbol: Symbol): boolean;
/** @internal */
export declare function getClassLikeDeclarationOfSymbol(symbol: Symbol): ClassLikeDeclaration | undefined;
/** @internal */
export declare function getObjectFlags(type: Type): ObjectFlags;
/** @internal */
export declare function forSomeAncestorDirectory(directory: string, callback: (directory: string) => boolean): boolean;
/** @internal */
export declare function isUMDExportSymbol(symbol: Symbol | undefined): boolean;
/** @internal */
export declare function showModuleSpecifier({ moduleSpecifier }: ImportDeclaration): string;
/** @internal */
export declare function getLastChild(node: Node): Node | undefined;
/**
 * Add a value to a set, and return true if it wasn't already present.
 *
 * @internal
 */
export declare function addToSeen<K>(seen: Map<K, true>, key: K): boolean;
/** @internal */
export declare function addToSeen<K, T>(seen: Map<K, T>, key: K, value: T): boolean;
/** @internal */
export declare function isObjectTypeDeclaration(node: Node): node is ObjectTypeDeclaration;
/** @internal */
export declare function isTypeNodeKind(kind: SyntaxKind): kind is TypeNodeSyntaxKind;
/** @internal */
export declare function isAccessExpression(node: Node): node is AccessExpression;
/** @internal */
export declare function getNameOfAccessExpression(node: AccessExpression): Expression;
/** @deprecated @internal */
export declare function isBundleFileTextLike(section: BundleFileSection): section is BundleFileTextLike;
/** @internal */
export declare function isNamedImportsOrExports(node: Node): node is NamedImportsOrExports;
/** @internal */
export declare function getLeftmostAccessExpression(expr: Expression): Expression;
/** @internal */
export declare function forEachNameInAccessChainWalkingLeft<T>(name: MemberName | StringLiteralLike, action: (name: MemberName | StringLiteralLike) => T | undefined): T | undefined;
/** @internal */
export declare function getLeftmostExpression(node: Expression, stopAtCallExpressions: boolean): Expression;
/** @internal */
export interface ObjectAllocator {
    getNodeConstructor(): new (kind: SyntaxKind, pos: number, end: number) => Node;
    getTokenConstructor(): new <TKind extends SyntaxKind>(kind: TKind, pos: number, end: number) => Token<TKind>;
    getIdentifierConstructor(): new (kind: SyntaxKind.Identifier, pos: number, end: number) => Identifier;
    getPrivateIdentifierConstructor(): new (kind: SyntaxKind.PrivateIdentifier, pos: number, end: number) => PrivateIdentifier;
    getSourceFileConstructor(): new (kind: SyntaxKind.SourceFile, pos: number, end: number) => SourceFile;
    getSymbolConstructor(): new (flags: SymbolFlags, name: __String) => Symbol;
    getTypeConstructor(): new (checker: TypeChecker, flags: TypeFlags) => Type;
    getSignatureConstructor(): new (checker: TypeChecker, flags: SignatureFlags) => Signature;
    getSourceMapSourceConstructor(): new (fileName: string, text: string, skipTrivia?: (pos: number) => number) => SourceMapSource;
}
declare function Symbol(this: Symbol, flags: SymbolFlags, name: __String): void;
declare function Type(this: Type, checker: TypeChecker, flags: TypeFlags): void;
declare function Signature(this: Signature, checker: TypeChecker, flags: SignatureFlags): void;
declare function Node(this: Mutable<Node>, kind: SyntaxKind, pos: number, end: number): void;
declare function Token(this: Mutable<Node>, kind: SyntaxKind, pos: number, end: number): void;
declare function Identifier(this: Mutable<Node>, kind: SyntaxKind, pos: number, end: number): void;
declare function SourceMapSource(this: SourceMapSource, fileName: string, text: string, skipTrivia?: (pos: number) => number): void;
/** @internal */
export declare const objectAllocator: ObjectAllocator;
/**
 * Used by `deprecatedCompat` to patch the object allocator to apply deprecations.
 * @internal
 */
export declare function addObjectAllocatorPatcher(fn: (objectAllocator: ObjectAllocator) => void): void;
/** @internal */
export declare function setObjectAllocator(alloc: ObjectAllocator): void;
/** @internal */
export declare function formatStringFromArgs(text: string, args: ArrayLike<string | number>, baseIndex?: number): string;
/** @internal */
export declare function setLocalizedDiagnosticMessages(messages: MapLike<string> | undefined): void;
/** @internal */
export declare function maybeSetLocalizedDiagnosticMessages(getMessages: undefined | (() => MapLike<string> | undefined)): void;
/** @internal */
export declare function getLocaleSpecificMessage(message: DiagnosticMessage): string;
/** @internal */
export declare function createDetachedDiagnostic(fileName: string, start: number, length: number, message: DiagnosticMessage, ...args: DiagnosticArguments): DiagnosticWithDetachedLocation;
/** @internal */
export declare function attachFileToDiagnostics(diagnostics: DiagnosticWithDetachedLocation[], file: SourceFile): DiagnosticWithLocation[];
/** @internal */
export declare function createFileDiagnostic(file: SourceFile, start: number, length: number, message: DiagnosticMessage, ...args: DiagnosticArguments): DiagnosticWithLocation;
/** @internal */
export declare function formatMessage(_dummy: any, message: DiagnosticMessage, ...args: DiagnosticArguments): string;
/** @internal */
export declare function createCompilerDiagnostic(message: DiagnosticMessage, ...args: DiagnosticArguments): Diagnostic;
/** @internal */
export declare function createCompilerDiagnosticFromMessageChain(chain: DiagnosticMessageChain, relatedInformation?: DiagnosticRelatedInformation[]): Diagnostic;
/** @internal */
export declare function chainDiagnosticMessages(details: DiagnosticMessageChain | DiagnosticMessageChain[] | undefined, message: DiagnosticMessage, ...args: DiagnosticArguments): DiagnosticMessageChain;
/** @internal */
export declare function concatenateDiagnosticMessageChains(headChain: DiagnosticMessageChain, tailChain: DiagnosticMessageChain): void;
/** @internal */
export declare function compareDiagnostics(d1: Diagnostic, d2: Diagnostic): Comparison;
/** @internal */
export declare function compareDiagnosticsSkipRelatedInformation(d1: Diagnostic, d2: Diagnostic): Comparison;
/** @internal */
export declare function getLanguageVariant(scriptKind: ScriptKind): LanguageVariant;
/** @internal */
export declare function getSetExternalModuleIndicator(options: CompilerOptions): (file: SourceFile) => void;
/** @internal */
export declare function getEmitScriptTarget(compilerOptions: {
    module?: CompilerOptions["module"];
    target?: CompilerOptions["target"];
}): ScriptTarget;
/** @internal */
export declare function getEmitModuleKind(compilerOptions: {
    module?: CompilerOptions["module"];
    target?: CompilerOptions["target"];
}): ModuleKind;
/** @internal */
export declare function emitModuleKindIsNonNodeESM(moduleKind: ModuleKind): boolean;
/** @internal */
export declare function getEmitModuleResolutionKind(compilerOptions: CompilerOptions): ModuleResolutionKind;
/** @internal */
export declare function getEmitModuleDetectionKind(options: CompilerOptions): ModuleDetectionKind;
/** @internal */
export declare function hasJsonModuleEmitEnabled(options: CompilerOptions): boolean;
/** @internal */
export declare function getIsolatedModules(options: CompilerOptions): boolean;
/** @internal */
export declare function importNameElisionDisabled(options: CompilerOptions): boolean | undefined;
/** @internal */
export declare function unreachableCodeIsError(options: CompilerOptions): boolean;
/** @internal */
export declare function unusedLabelIsError(options: CompilerOptions): boolean;
/** @internal */
export declare function getAreDeclarationMapsEnabled(options: CompilerOptions): boolean;
/** @internal */
export declare function getESModuleInterop(compilerOptions: CompilerOptions): boolean | undefined;
/** @internal */
export declare function getAllowSyntheticDefaultImports(compilerOptions: CompilerOptions): boolean;
/** @internal */
export declare function moduleResolutionSupportsPackageJsonExportsAndImports(moduleResolution: ModuleResolutionKind): boolean;
/** @internal */
export declare function shouldResolveJsRequire(compilerOptions: CompilerOptions): boolean;
/** @internal */
export declare function getResolvePackageJsonExports(compilerOptions: CompilerOptions): boolean;
/** @internal */
export declare function getResolvePackageJsonImports(compilerOptions: CompilerOptions): boolean;
/** @internal */
export declare function getResolveJsonModule(compilerOptions: CompilerOptions): boolean;
/** @internal */
export declare function getEmitDeclarations(compilerOptions: CompilerOptions): boolean;
/** @internal */
export declare function shouldPreserveConstEnums(compilerOptions: CompilerOptions): boolean;
/** @internal */
export declare function isIncrementalCompilation(options: CompilerOptions): boolean;
/** @internal */
export type StrictOptionName = "noImplicitAny" | "noImplicitThis" | "strictNullChecks" | "strictFunctionTypes" | "strictBindCallApply" | "strictPropertyInitialization" | "alwaysStrict" | "useUnknownInCatchVariables";
/** @internal */
export declare function getStrictOptionValue(compilerOptions: CompilerOptions, flag: StrictOptionName): boolean;
/** @internal */
export declare function getAllowJSCompilerOption(compilerOptions: CompilerOptions): boolean;
/** @internal */
export declare function getUseDefineForClassFields(compilerOptions: CompilerOptions): boolean;
/** @internal */
export declare function compilerOptionsAffectSemanticDiagnostics(newOptions: CompilerOptions, oldOptions: CompilerOptions): boolean;
/** @internal */
export declare function compilerOptionsAffectEmit(newOptions: CompilerOptions, oldOptions: CompilerOptions): boolean;
/** @internal */
export declare function compilerOptionsAffectDeclarationPath(newOptions: CompilerOptions, oldOptions: CompilerOptions): boolean;
/** @internal */
export declare function getCompilerOptionValue(options: CompilerOptions, option: CommandLineOption): unknown;
/** @internal */
export declare function getJSXTransformEnabled(options: CompilerOptions): boolean;
/** @internal */
export declare function getJSXImplicitImportBase(compilerOptions: CompilerOptions, file?: SourceFile): string | undefined;
/** @internal */
export declare function getJSXRuntimeImport(base: string | undefined, options: CompilerOptions): string | undefined;
/** @internal */
export declare function hasZeroOrOneAsteriskCharacter(str: string): boolean;
/** @internal */
export interface SymlinkedDirectory {
    /** Matches the casing returned by `realpath`.  Used to compute the `realpath` of children. */
    real: string;
    /** toPath(real).  Stored to avoid repeated recomputation. */
    realPath: Path;
}
/** @internal */
export interface SymlinkCache {
    /** Gets a map from symlink to realpath. Keys have trailing directory separators. */
    getSymlinkedDirectories(): ReadonlyMap<Path, SymlinkedDirectory | false> | undefined;
    /** Gets a map from realpath to symlinks. Keys have trailing directory separators. */
    getSymlinkedDirectoriesByRealpath(): MultiMap<Path, string> | undefined;
    /** Gets a map from symlink to realpath */
    getSymlinkedFiles(): ReadonlyMap<Path, string> | undefined;
    setSymlinkedDirectory(symlink: string, real: SymlinkedDirectory | false): void;
    setSymlinkedFile(symlinkPath: Path, real: string): void;
    /**
     * @internal
     * Uses resolvedTypeReferenceDirectives from program instead of from files, since files
     * don't include automatic type reference directives. Must be called only when
     * `hasProcessedResolutions` returns false (once per cache instance).
     */
    setSymlinksFromResolutions(files: readonly SourceFile[], typeReferenceDirectives: ModeAwareCache<ResolvedTypeReferenceDirectiveWithFailedLookupLocations>): void;
    /**
     * @internal
     * Whether `setSymlinksFromResolutions` has already been called.
     */
    hasProcessedResolutions(): boolean;
}
/** @internal */
export declare function createSymlinkCache(cwd: string, getCanonicalFileName: GetCanonicalFileName): SymlinkCache;
/** @internal */
export declare function tryRemoveDirectoryPrefix(path: string, dirPath: string, getCanonicalFileName: GetCanonicalFileName): string | undefined;
/** @internal */
export declare function regExpEscape(text: string): string;
/** @internal */
export declare const commonPackageFolders: readonly string[];
/** @internal */
export declare function getRegularExpressionForWildcard(specs: readonly string[] | undefined, basePath: string, usage: "files" | "directories" | "exclude"): string | undefined;
/** @internal */
export declare function getRegularExpressionsForWildcards(specs: readonly string[] | undefined, basePath: string, usage: "files" | "directories" | "exclude"): readonly string[] | undefined;
/**
 * An "includes" path "foo" is implicitly a glob "foo/** /*" (without the space) if its last component has no extension,
 * and does not contain any glob characters itself.
 *
 * @internal
 */
export declare function isImplicitGlob(lastPathComponent: string): boolean;
/** @internal */
export declare function getPatternFromSpec(spec: string, basePath: string, usage: "files" | "directories" | "exclude"): string | undefined;
/** @internal */
export interface FileSystemEntries {
    readonly files: readonly string[];
    readonly directories: readonly string[];
}
/** @internal */
export interface FileMatcherPatterns {
    /** One pattern for each "include" spec. */
    includeFilePatterns: readonly string[] | undefined;
    /** One pattern matching one of any of the "include" specs. */
    includeFilePattern: string | undefined;
    includeDirectoryPattern: string | undefined;
    excludePattern: string | undefined;
    basePaths: readonly string[];
}
/**
 * @param path directory of the tsconfig.json
 *
 * @internal
 */
export declare function getFileMatcherPatterns(path: string, excludes: readonly string[] | undefined, includes: readonly string[] | undefined, useCaseSensitiveFileNames: boolean, currentDirectory: string): FileMatcherPatterns;
/** @internal */
export declare function getRegexFromPattern(pattern: string, useCaseSensitiveFileNames: boolean): RegExp;
/**
 * @param path directory of the tsconfig.json
 *
 * @internal
 */
export declare function matchFiles(path: string, extensions: readonly string[] | undefined, excludes: readonly string[] | undefined, includes: readonly string[] | undefined, useCaseSensitiveFileNames: boolean, currentDirectory: string, depth: number | undefined, getFileSystemEntries: (path: string) => FileSystemEntries, realpath: (path: string) => string): string[];
/** @internal */
export declare function ensureScriptKind(fileName: string, scriptKind: ScriptKind | undefined): ScriptKind;
/** @internal */
export declare function getScriptKindFromFileName(fileName: string): ScriptKind;
/**
 *  Groups of supported extensions in order of file resolution precedence. (eg, TS > TSX > DTS and seperately, CTS > DCTS)
 *
 * @internal
 */
export declare const supportedTSExtensions: readonly Extension[][];
/** @internal */
export declare const supportedTSExtensionsFlat: readonly Extension[];
/** @internal */
export declare const supportedJSExtensions: readonly Extension[][];
/** @internal */
export declare const supportedJSExtensionsFlat: readonly Extension[];
/** @internal */
export declare const supportedDeclarationExtensions: readonly Extension[];
/** @internal */
export declare const supportedTSImplementationExtensions: readonly Extension[];
/** @internal */
export declare const extensionsNotSupportingExtensionlessResolution: readonly Extension[];
/** @internal */
export declare function getSupportedExtensions(options?: CompilerOptions): readonly Extension[][];
/** @internal */
export declare function getSupportedExtensions(options?: CompilerOptions, extraFileExtensions?: readonly FileExtensionInfo[]): readonly string[][];
/** @internal */
export declare function getSupportedExtensionsWithJsonIfResolveJsonModule(options: CompilerOptions | undefined, supportedExtensions: readonly Extension[][]): readonly Extension[][];
/** @internal */
export declare function getSupportedExtensionsWithJsonIfResolveJsonModule(options: CompilerOptions | undefined, supportedExtensions: readonly string[][]): readonly string[][];
/** @internal */
export declare function hasJSFileExtension(fileName: string): boolean;
/** @internal */
export declare function hasTSFileExtension(fileName: string): boolean;
/**
 * @internal
 * Corresponds to UserPreferences#importPathEnding
 */
export declare const enum ModuleSpecifierEnding {
    Minimal = 0,
    Index = 1,
    JsExtension = 2,
    TsExtension = 3
}
/** @internal */
export declare function usesExtensionsOnImports({ imports }: SourceFile, hasExtension?: (text: string) => boolean): boolean;
/** @internal */
export declare function getModuleSpecifierEndingPreference(preference: UserPreferences["importModuleSpecifierEnding"], resolutionMode: ResolutionMode, compilerOptions: CompilerOptions, sourceFile: SourceFile): ModuleSpecifierEnding;
/** @internal */
export declare function isSupportedSourceFileName(fileName: string, compilerOptions?: CompilerOptions, extraFileExtensions?: readonly FileExtensionInfo[]): boolean;
/** @internal */
export declare function compareNumberOfDirectorySeparators(path1: string, path2: string): Comparison;
/** @internal */
export declare function removeFileExtension(path: string): string;
/** @internal */
export declare function tryRemoveExtension(path: string, extension: string): string | undefined;
/** @internal */
export declare function removeExtension(path: string, extension: string): string;
/** @internal */
export declare function changeExtension<T extends string | Path>(path: T, newExtension: string): T;
/**
 * Returns the input if there are no stars, a pattern if there is exactly one,
 * and undefined if there are more.
 *
 * @internal
 */
export declare function tryParsePattern(pattern: string): string | Pattern | undefined;
/** @internal */
export declare function tryParsePatterns(paths: MapLike<string[]>): (string | Pattern)[];
/** @internal */
export declare function positionIsSynthesized(pos: number): boolean;
/**
 * True if an extension is one of the supported TypeScript extensions.
 *
 * @internal
 */
export declare function extensionIsTS(ext: string): boolean;
/** @internal */
export declare function resolutionExtensionIsTSOrJson(ext: string): boolean;
/**
 * Gets the extension from a path.
 * Path must have a valid extension.
 *
 * @internal
 */
export declare function extensionFromPath(path: string): Extension;
/** @internal */
export declare function isAnySupportedFileExtension(path: string): boolean;
/** @internal */
export declare function tryGetExtensionFromPath(path: string): Extension | undefined;
/** @internal */
export declare function isCheckJsEnabledForFile(sourceFile: SourceFile, compilerOptions: CompilerOptions): boolean | undefined;
/** @internal */
export declare const emptyFileSystemEntries: FileSystemEntries;
/**
 * patternOrStrings contains both patterns (containing "*") and regular strings.
 * Return an exact match if possible, or a pattern match, or undefined.
 * (These are verified by verifyCompilerOptions to have 0 or 1 "*" characters.)
 *
 * @internal
 */
export declare function matchPatternOrExact(patternOrStrings: readonly (string | Pattern)[], candidate: string): string | Pattern | undefined;
/** @internal */
export type Mutable<T extends object> = {
    -readonly [K in keyof T]: T[K];
};
/** @internal */
export declare function sliceAfter<T>(arr: readonly T[], value: T): readonly T[];
/** @internal */
export declare function addRelatedInfo<T extends Diagnostic>(diagnostic: T, ...relatedInformation: DiagnosticRelatedInformation[]): T;
/** @internal */
export declare function minAndMax<T>(arr: readonly T[], getValue: (value: T) => number): {
    readonly min: number;
    readonly max: number;
};
/** @internal */
export declare function rangeOfNode(node: Node): TextRange;
/** @internal */
export declare function rangeOfTypeParameters(sourceFile: SourceFile, typeParameters: NodeArray<TypeParameterDeclaration>): TextRange;
/** @internal */
export interface HostWithIsSourceOfProjectReferenceRedirect {
    isSourceOfProjectReferenceRedirect(fileName: string): boolean;
}
/** @internal */
export declare function skipTypeChecking(sourceFile: SourceFile, options: CompilerOptions, host: HostWithIsSourceOfProjectReferenceRedirect): boolean;
/** @internal */
export declare function isJsonEqual(a: unknown, b: unknown): boolean;
/**
 * Converts a bigint literal string, e.g. `0x1234n`,
 * to its decimal string representation, e.g. `4660`.
 *
 * @internal
 */
export declare function parsePseudoBigInt(stringValue: string): string;
/** @internal */
export declare function pseudoBigIntToString({ negative, base10Value }: PseudoBigInt): string;
/** @internal */
export declare function parseBigInt(text: string): PseudoBigInt | undefined;
/**
 * @internal
 * @param text a valid bigint string excluding a trailing `n`, but including a possible prefix `-`. Use `isValidBigIntString(text, roundTripOnly)` before calling this function.
 */
export declare function parseValidBigInt(text: string): PseudoBigInt;
/**
 * @internal
 * Tests whether the provided string can be parsed as a bigint.
 * @param s The string to test.
 * @param roundTripOnly Indicates the resulting bigint matches the input when converted back to a string.
 */
export declare function isValidBigIntString(s: string, roundTripOnly: boolean): boolean;
/** @internal */
export declare function isValidTypeOnlyAliasUseSite(useSite: Node): boolean;
/** @internal */
export declare function isIdentifierTypeReference(node: Node): node is TypeReferenceNode & {
    typeName: Identifier;
};
/** @internal */
export declare function arrayIsHomogeneous<T>(array: readonly T[], comparer?: EqualityComparer<T>): boolean;
/**
 * Bypasses immutability and directly sets the `pos` property of a `TextRange` or `Node`.
 *
 * @internal
 */
export declare function setTextRangePos<T extends ReadonlyTextRange>(range: T, pos: number): T;
/**
 * Bypasses immutability and directly sets the `end` property of a `TextRange` or `Node`.
 *
 * @internal
 */
export declare function setTextRangeEnd<T extends ReadonlyTextRange>(range: T, end: number): T;
/**
 * Bypasses immutability and directly sets the `pos` and `end` properties of a `TextRange` or `Node`.
 *
 * @internal
 */
export declare function setTextRangePosEnd<T extends ReadonlyTextRange>(range: T, pos: number, end: number): T;
/**
 * Bypasses immutability and directly sets the `pos` and `end` properties of a `TextRange` or `Node` from the
 * provided position and width.
 *
 * @internal
 */
export declare function setTextRangePosWidth<T extends ReadonlyTextRange>(range: T, pos: number, width: number): T;
/**
 * Bypasses immutability and directly sets the `flags` property of a `Node`.
 *
 * @internal
 */
export declare function setNodeFlags<T extends Node>(node: T, newFlags: NodeFlags): T;
/** @internal */
export declare function setNodeFlags<T extends Node>(node: T | undefined, newFlags: NodeFlags): T | undefined;
/**
 * Bypasses immutability and directly sets the `parent` property of a `Node`.
 *
 * @internal
 */
export declare function setParent<T extends Node>(child: T, parent: T["parent"] | undefined): T;
/** @internal */
export declare function setParent<T extends Node>(child: T | undefined, parent: T["parent"] | undefined): T | undefined;
/**
 * Bypasses immutability and directly sets the `parent` property of each `Node` in an array of nodes, if is not already set.
 *
 * @internal
 */
export declare function setEachParent<T extends readonly Node[]>(children: T, parent: T[number]["parent"]): T;
/** @internal */
export declare function setEachParent<T extends readonly Node[]>(children: T | undefined, parent: T[number]["parent"]): T | undefined;
/**
 * Bypasses immutability and directly sets the `parent` property of each `Node` recursively.
 * @param rootNode The root node from which to start the recursion.
 * @param incremental When `true`, only recursively descends through nodes whose `parent` pointers are incorrect.
 * This allows us to quickly bail out of setting `parent` for subtrees during incremental parsing.
 *
 * @internal
 */
export declare function setParentRecursive<T extends Node>(rootNode: T, incremental: boolean): T;
/** @internal */
export declare function setParentRecursive<T extends Node>(rootNode: T | undefined, incremental: boolean): T | undefined;
/**
 * Determines whether the provided node is an ArrayLiteralExpression that contains no missing elements.
 *
 * @internal
 */
export declare function isPackedArrayLiteral(node: Expression): boolean;
/**
 * Indicates whether the result of an `Expression` will be unused.
 *
 * NOTE: This requires a node with a valid `parent` pointer.
 *
 * @internal
 */
export declare function expressionResultIsUnused(node: Expression): boolean;
/** @internal */
export declare function containsIgnoredPath(path: string): boolean;
/** @internal */
export declare function getContainingNodeArray(node: Node): NodeArray<Node> | undefined;
/** @internal */
export declare function hasContextSensitiveParameters(node: FunctionLikeDeclaration): boolean;
/** @internal */
export declare function isInfinityOrNaNString(name: string | __String): boolean;
/** @internal */
export declare function isCatchClauseVariableDeclaration(node: Node): boolean;
/** @internal */
export declare function isParameterOrCatchClauseVariable(symbol: Symbol): boolean;
/** @internal */
export declare function isFunctionExpressionOrArrowFunction(node: Node): node is FunctionExpression | ArrowFunction;
/** @internal */
export declare function escapeSnippetText(text: string): string;
/** @internal */
export declare function isNumericLiteralName(name: string | __String): boolean;
/** @internal */
export declare function createPropertyNameNodeForIdentifierOrLiteral(name: string, target: ScriptTarget, singleQuote?: boolean, stringNamed?: boolean): Identifier | StringLiteral | NumericLiteral;
/** @internal */
export declare function isThisTypeParameter(type: Type): boolean;
/** @internal */
export interface NodeModulePathParts {
    readonly topLevelNodeModulesIndex: number;
    readonly topLevelPackageNameIndex: number;
    readonly packageRootIndex: number;
    readonly fileNameIndex: number;
}
/** @internal */
export declare function getNodeModulePathParts(fullPath: string): NodeModulePathParts | undefined;
/** @internal */
export declare function getParameterTypeNode(parameter: ParameterDeclaration | JSDocParameterTag): TypeNode | undefined;
/** @internal */
export declare function isTypeDeclaration(node: Node): node is TypeParameterDeclaration | ClassDeclaration | InterfaceDeclaration | TypeAliasDeclaration | JSDocTypedefTag | JSDocCallbackTag | JSDocEnumTag | EnumDeclaration | ImportClause | ImportSpecifier | ExportSpecifier;
/** @internal */
export declare function canHaveExportModifier(node: Node): node is Extract<HasModifiers, Statement>;
/** @internal */
export declare function isOptionalJSDocPropertyLikeTag(node: Node): node is JSDocPropertyLikeTag;
/** @internal */
export declare function canUsePropertyAccess(name: string, languageVersion: ScriptTarget): boolean;
/** @internal */
export declare function hasTabstop(node: Node): boolean;
/** @internal */
export declare function isJSDocOptionalParameter(node: ParameterDeclaration): boolean;
/** @internal */
export declare function isOptionalDeclaration(declaration: Declaration): boolean;
/** @internal */
export declare function isNonNullAccess(node: Node): node is AccessExpression;
/** @internal */
export declare function isJSDocSatisfiesExpression(node: Node): node is JSDocSatisfiesExpression;
/** @internal */
export declare function getJSDocSatisfiesExpressionType(node: JSDocSatisfiesExpression): TypeNode;
/** @internal */
export declare function tryGetJSDocSatisfiesTypeNode(node: Node): TypeNode | undefined;
/** @internal */
export declare function getEscapedTextOfJsxAttributeName(node: JsxAttributeName): __String;
/** @internal */
export declare function getTextOfJsxAttributeName(node: JsxAttributeName): string;
/** @internal */
export declare function isJsxAttributeName(node: Node): node is JsxAttributeName;
/** @internal */
export declare function getEscapedTextOfJsxNamespacedName(node: JsxNamespacedName): __String;
/** @internal */
export declare function getTextOfJsxNamespacedName(node: JsxNamespacedName): string;
/** @internal */
export declare function intrinsicTagNameToString(node: Identifier | JsxNamespacedName): string;
export {};
//# sourceMappingURL=utilities.d.ts.map