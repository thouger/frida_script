import { BaseNodeFactory, Diagnostic, DiagnosticMessage, EntityName, JSDoc, JSDocTypeExpression, JsonSourceFile, JsxTagNameExpression, Node, NodeArray, NodeFactory, PackageJsonInfo, PragmaContext, ResolutionMode, ScriptKind, ScriptTarget, SourceFile, TextChangeRange } from "./_namespaces/ts";
/**
 * NOTE: You should not use this, it is only exported to support `createNode` in `~/src/deprecatedCompat/deprecations.ts`.
 *
 * @internal
 */
export declare const parseBaseNodeFactory: BaseNodeFactory;
/** @internal */
export declare const parseNodeFactory: NodeFactory;
/** @internal */
export declare function isJSDocLikeText(text: string, start: number): boolean;
/** @internal */
export declare function isFileProbablyExternalModule(sourceFile: SourceFile): Node | undefined;
/**
 * Invokes a callback for each child of the given node. The 'cbNode' callback is invoked for all child nodes
 * stored in properties. If a 'cbNodes' callback is specified, it is invoked for embedded arrays; otherwise,
 * embedded arrays are flattened and the 'cbNode' callback is invoked for each element. If a callback returns
 * a truthy value, iteration stops and that value is returned. Otherwise, undefined is returned.
 *
 * @param node a given node to visit its children
 * @param cbNode a callback to be invoked for all child nodes
 * @param cbNodes a callback to be invoked for embedded array
 *
 * @remarks `forEachChild` must visit the children of a node in the order
 * that they appear in the source code. The language service depends on this property to locate nodes by position.
 */
export declare function forEachChild<T>(node: Node, cbNode: (node: Node) => T | undefined, cbNodes?: (nodes: NodeArray<Node>) => T | undefined): T | undefined;
/**
 * Invokes a callback for each child of the given node. The 'cbNode' callback is invoked for all child nodes
 * stored in properties. If a 'cbNodes' callback is specified, it is invoked for embedded arrays; additionally,
 * unlike `forEachChild`, embedded arrays are flattened and the 'cbNode' callback is invoked for each element.
 *  If a callback returns a truthy value, iteration stops and that value is returned. Otherwise, undefined is returned.
 *
 * @param node a given node to visit its children
 * @param cbNode a callback to be invoked for all child nodes
 * @param cbNodes a callback to be invoked for embedded array
 *
 * @remarks Unlike `forEachChild`, `forEachChildRecursively` handles recursively invoking the traversal on each child node found,
 * and while doing so, handles traversing the structure without relying on the callstack to encode the tree structure.
 *
 * @internal
 */
export declare function forEachChildRecursively<T>(rootNode: Node, cbNode: (node: Node, parent: Node) => T | "skip" | undefined, cbNodes?: (nodes: NodeArray<Node>, parent: Node) => T | "skip" | undefined): T | undefined;
export interface CreateSourceFileOptions {
    languageVersion: ScriptTarget;
    /**
     * Controls the format the file is detected as - this can be derived from only the path
     * and files on disk, but needs to be done with a module resolution cache in scope to be performant.
     * This is usually `undefined` for compilations that do not have `moduleResolution` values of `node16` or `nodenext`.
     */
    impliedNodeFormat?: ResolutionMode;
    /**
     * Controls how module-y-ness is set for the given file. Usually the result of calling
     * `getSetExternalModuleIndicator` on a valid `CompilerOptions` object. If not present, the default
     * check specified by `isFileProbablyExternalModule` will be used to set the field.
     */
    setExternalModuleIndicator?: (file: SourceFile) => void;
    /** @internal */ packageJsonLocations?: readonly string[];
    /** @internal */ packageJsonScope?: PackageJsonInfo;
}
export declare function createSourceFile(fileName: string, sourceText: string, languageVersionOrOptions: ScriptTarget | CreateSourceFileOptions, setParentNodes?: boolean, scriptKind?: ScriptKind): SourceFile;
export declare function parseIsolatedEntityName(text: string, languageVersion: ScriptTarget): EntityName | undefined;
/**
 * Parse json text into SyntaxTree and return node and parse errors if any
 * @param fileName
 * @param sourceText
 */
export declare function parseJsonText(fileName: string, sourceText: string): JsonSourceFile;
export declare function isExternalModule(file: SourceFile): boolean;
export declare function updateSourceFile(sourceFile: SourceFile, newText: string, textChangeRange: TextChangeRange, aggressiveChecks?: boolean): SourceFile;
/** @internal */
export declare function parseIsolatedJSDocComment(content: string, start?: number, length?: number): {
    jsDoc: JSDoc;
    diagnostics: Diagnostic[];
} | undefined;
/** @internal */
export declare function parseJSDocTypeExpressionForTests(content: string, start?: number, length?: number): {
    jsDocTypeExpression: JSDocTypeExpression;
    diagnostics: Diagnostic[];
} | undefined;
/** @internal */
export declare function isDeclarationFileName(fileName: string): boolean;
/** @internal */
export declare function processCommentPragmas(context: PragmaContext, sourceText: string): void;
/** @internal */
export type PragmaDiagnosticReporter = (pos: number, length: number, message: DiagnosticMessage) => void;
/** @internal */
export declare function processPragmasIntoFields(context: PragmaContext, reportDiagnostic: PragmaDiagnosticReporter): void;
/** @internal */
export declare function tagNamesAreEquivalent(lhs: JsxTagNameExpression, rhs: JsxTagNameExpression): boolean;
//# sourceMappingURL=parser.d.ts.map