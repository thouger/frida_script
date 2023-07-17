import { CancellationToken, CodeAction, CompilerOptions, CompletionEntry, CompletionEntryData, CompletionEntryDetails, CompletionInfo, CompletionsTriggerCharacter, CompletionTriggerKind, formatting, Identifier, JSDocTagInfo, JsxAttributes, LanguageServiceHost, Node, ObjectLiteralExpression, Program, PropertyAccessExpression, ScriptElementKind, ScriptTarget, SortedArray, SourceFile, Symbol, SymbolDisplayPart, TextSpan, TokenSyntaxKind, Type, TypeChecker, UserPreferences } from "./_namespaces/ts";
/** @internal */
export declare const moduleSpecifierResolutionLimit = 100;
/** @internal */
export declare const moduleSpecifierResolutionCacheAttemptLimit = 1000;
/** @internal */
export type Log = (message: string) => void;
/** @internal */
export type SortText = string & {
    __sortText: any;
};
/** @internal */
export declare const SortText: {
    LocalDeclarationPriority: SortText;
    LocationPriority: SortText;
    OptionalMember: SortText;
    MemberDeclaredBySpreadAssignment: SortText;
    SuggestedClassMembers: SortText;
    GlobalsOrKeywords: SortText;
    AutoImportSuggestions: SortText;
    ClassMemberSnippets: SortText;
    JavascriptIdentifiers: SortText;
    Deprecated(sortText: SortText): SortText;
    ObjectLiteralProperty(presetSortText: SortText, symbolDisplayName: string): SortText;
    SortBelow(sortText: SortText): SortText;
};
/**
 * Special values for `CompletionInfo['source']` used to disambiguate
 * completion items with the same `name`. (Each completion item must
 * have a unique name/source combination, because those two fields
 * comprise `CompletionEntryIdentifier` in `getCompletionEntryDetails`.
 *
 * When the completion item is an auto-import suggestion, the source
 * is the module specifier of the suggestion. To avoid collisions,
 * the values here should not be a module specifier we would ever
 * generate for an auto-import.
 *
 * @internal
 */
export declare enum CompletionSource {
    /** Completions that require `this.` insertion text */
    ThisProperty = "ThisProperty/",
    /** Auto-import that comes attached to a class member snippet */
    ClassMemberSnippet = "ClassMemberSnippet/",
    /** A type-only import that needs to be promoted in order to be used at the completion location */
    TypeOnlyAlias = "TypeOnlyAlias/",
    /** Auto-import that comes attached to an object literal method snippet */
    ObjectLiteralMethodSnippet = "ObjectLiteralMethodSnippet/",
    /** Case completions for switch statements */
    SwitchCases = "SwitchCases/"
}
/** @internal */
export declare const enum SymbolOriginInfoKind {
    ThisType = 1,
    SymbolMember = 2,
    Export = 4,
    Promise = 8,
    Nullable = 16,
    ResolvedExport = 32,
    TypeOnlyAlias = 64,
    ObjectLiteralMethod = 128,
    Ignore = 256,
    ComputedPropertyName = 512,
    SymbolMemberNoExport = 2,
    SymbolMemberExport = 6
}
/** @internal */
export interface SymbolOriginInfo {
    kind: SymbolOriginInfoKind;
    isDefaultExport?: boolean;
    isFromPackageJson?: boolean;
    fileName?: string;
}
/** @internal */
export interface UniqueNameSet {
    add(name: string): void;
    has(name: string): boolean;
}
/**
 * Map from symbol index in `symbols` -> SymbolOriginInfo.
 *
 * @internal
 */
export type SymbolOriginInfoMap = Record<number, SymbolOriginInfo>;
/**
 * Map from symbol id -> SortText.
 *
 * @internal
 */
export type SymbolSortTextMap = (SortText | undefined)[];
/** @internal */
export declare function getCompletionsAtPosition(host: LanguageServiceHost, program: Program, log: Log, sourceFile: SourceFile, position: number, preferences: UserPreferences, triggerCharacter: CompletionsTriggerCharacter | undefined, completionKind: CompletionTriggerKind | undefined, cancellationToken: CancellationToken, formatContext?: formatting.FormatContext, includeSymbol?: boolean): CompletionInfo | undefined;
/** @internal */
export declare function getCompletionEntriesFromSymbols(symbols: readonly Symbol[], entries: SortedArray<CompletionEntry>, replacementToken: Node | undefined, contextToken: Node | undefined, location: Node, position: number, sourceFile: SourceFile, host: LanguageServiceHost, program: Program, target: ScriptTarget, log: Log, kind: CompletionKind, preferences: UserPreferences, compilerOptions: CompilerOptions, formatContext: formatting.FormatContext | undefined, isTypeOnlyLocation?: boolean, propertyAccessToConvert?: PropertyAccessExpression, jsxIdentifierExpected?: boolean, isJsxInitializer?: IsJsxInitializer, importStatementCompletion?: ImportStatementCompletionInfo, recommendedCompletion?: Symbol, symbolToOriginInfoMap?: SymbolOriginInfoMap, symbolToSortTextMap?: SymbolSortTextMap, isJsxIdentifierExpected?: boolean, isRightOfOpenTag?: boolean, includeSymbol?: boolean): UniqueNameSet;
/** @internal */
export interface CompletionEntryIdentifier {
    name: string;
    source?: string;
    data?: CompletionEntryData;
}
/** @internal */
export declare function getCompletionEntryDetails(program: Program, log: Log, sourceFile: SourceFile, position: number, entryId: CompletionEntryIdentifier, host: LanguageServiceHost, formatContext: formatting.FormatContext, preferences: UserPreferences, cancellationToken: CancellationToken): CompletionEntryDetails | undefined;
/** @internal */
export declare function createCompletionDetailsForSymbol(symbol: Symbol, name: string, checker: TypeChecker, sourceFile: SourceFile, location: Node, cancellationToken: CancellationToken, codeActions?: CodeAction[], sourceDisplay?: SymbolDisplayPart[]): CompletionEntryDetails;
/** @internal */
export declare function createCompletionDetails(name: string, kindModifiers: string, kind: ScriptElementKind, displayParts: SymbolDisplayPart[], documentation?: SymbolDisplayPart[], tags?: JSDocTagInfo[], codeActions?: CodeAction[], source?: SymbolDisplayPart[]): CompletionEntryDetails;
/** @internal */
export declare function getCompletionEntrySymbol(program: Program, log: Log, sourceFile: SourceFile, position: number, entryId: CompletionEntryIdentifier, host: LanguageServiceHost, preferences: UserPreferences): Symbol | undefined;
/**
 * true: after the `=` sign but no identifier has been typed yet. Else is the Identifier after the initializer.
 *
 * @internal
 */
export type IsJsxInitializer = boolean | Identifier;
/** @internal */
export declare const enum CompletionKind {
    ObjectPropertyDeclaration = 0,
    Global = 1,
    PropertyAccess = 2,
    MemberLike = 3,
    String = 4,
    None = 5
}
/** @internal */
export declare function getPropertiesForObjectExpression(contextualType: Type, completionsType: Type | undefined, obj: ObjectLiteralExpression | JsxAttributes, checker: TypeChecker): Symbol[];
/** @internal */
export interface ImportStatementCompletionInfo {
    isKeywordOnlyCompletion: boolean;
    keywordCompletion: TokenSyntaxKind | undefined;
    isNewIdentifierLocation: boolean;
    isTopLevelTypeOnly: boolean;
    couldBeTypeOnlyImportSpecifier: boolean;
    replacementSpan: TextSpan | undefined;
}
//# sourceMappingURL=completions.d.ts.map