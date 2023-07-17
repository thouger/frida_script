import { JSDocTagInfo, Node, ScriptElementKind, SemanticMeaning, SourceFile, Symbol, SymbolDisplayPart, TypeChecker } from "./_namespaces/ts";
/** @internal */
export declare function getSymbolKind(typeChecker: TypeChecker, symbol: Symbol, location: Node): ScriptElementKind;
/** @internal */
export declare function getSymbolModifiers(typeChecker: TypeChecker, symbol: Symbol): string;
/** @internal */
export interface SymbolDisplayPartsDocumentationAndSymbolKind {
    displayParts: SymbolDisplayPart[];
    documentation: SymbolDisplayPart[];
    symbolKind: ScriptElementKind;
    tags: JSDocTagInfo[] | undefined;
}
/** @internal */
export declare function getSymbolDisplayPartsDocumentationAndSymbolKind(typeChecker: TypeChecker, symbol: Symbol, sourceFile: SourceFile, enclosingDeclaration: Node | undefined, location: Node, semanticMeaning?: SemanticMeaning, alias?: Symbol): SymbolDisplayPartsDocumentationAndSymbolKind;
//# sourceMappingURL=symbolDisplay.d.ts.map