import { __String, CancellationToken, CompilerOptions, CreateSourceFileOptions, DocumentRegistry, EditorOptions, EditorSettings, EmitTextWriter, FormatCodeOptions, FormatCodeSettings, HostCancellationToken, IScriptSnapshot, JsxAttributes, LanguageService, LanguageServiceHost, LanguageServiceMode, Node, ObjectLiteralElement, ObjectLiteralExpression, PropertyName, ScriptKind, ScriptTarget, SourceFile, Symbol, SymbolDisplayPart, TextChangeRange, Type, TypeChecker } from "./_namespaces/ts";
/** The version of the language service API */
export declare const servicesVersion = "0.8";
/** @internal */
export interface DisplayPartsSymbolWriter extends EmitTextWriter {
    displayParts(): SymbolDisplayPart[];
}
/** @internal */
export declare function toEditorSettings(options: FormatCodeOptions | FormatCodeSettings): FormatCodeSettings;
export declare function toEditorSettings(options: EditorOptions | EditorSettings): EditorSettings;
export declare function displayPartsToString(displayParts: SymbolDisplayPart[] | undefined): string;
export declare function getDefaultCompilerOptions(): CompilerOptions;
export declare function getSupportedCodeFixes(): readonly string[];
export declare function createLanguageServiceSourceFile(fileName: string, scriptSnapshot: IScriptSnapshot, scriptTargetOrOptions: ScriptTarget | CreateSourceFileOptions, version: string, setNodeParents: boolean, scriptKind?: ScriptKind): SourceFile;
export declare function updateLanguageServiceSourceFile(sourceFile: SourceFile, scriptSnapshot: IScriptSnapshot, version: string, textChangeRange: TextChangeRange | undefined, aggressiveChecks?: boolean): SourceFile;
/**
 * A cancellation that throttles calls to the host
 *
 * @internal
 */
export declare class ThrottledCancellationToken implements CancellationToken {
    private hostCancellationToken;
    private readonly throttleWaitMilliseconds;
    private lastCancellationCheckTime;
    constructor(hostCancellationToken: HostCancellationToken, throttleWaitMilliseconds?: number);
    isCancellationRequested(): boolean;
    throwIfCancellationRequested(): void;
}
export declare function createLanguageService(host: LanguageServiceHost, documentRegistry?: DocumentRegistry, syntaxOnlyOrLanguageServiceMode?: boolean | LanguageServiceMode): LanguageService;
/**
 * Names in the name table are escaped, so an identifier `__foo` will have a name table entry `___foo`.
 *
 * @internal
 */
export declare function getNameTable(sourceFile: SourceFile): Map<__String, number>;
/**
 * Returns the containing object literal property declaration given a possible name node, e.g. "a" in x = { "a": 1 }
 *
 * @internal
 */
export declare function getContainingObjectLiteralElement(node: Node): ObjectLiteralElementWithName | undefined;
/** @internal */
export type ObjectLiteralElementWithName = ObjectLiteralElement & {
    name: PropertyName;
    parent: ObjectLiteralExpression | JsxAttributes;
};
/**
 * Gets all symbols for one property. Does not get symbols for every property.
 *
 * @internal
 */
export declare function getPropertySymbolsFromContextualType(node: ObjectLiteralElementWithName, checker: TypeChecker, contextualType: Type, unionSymbolOk: boolean): readonly Symbol[];
/**
 * Get the path of the default library files (lib.d.ts) as distributed with the typescript
 * node package.
 * The functionality is not supported if the ts module is consumed outside of a node module.
 */
export declare function getDefaultLibFilePath(options: CompilerOptions): string;
//# sourceMappingURL=services.d.ts.map