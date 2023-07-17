import { Declaration, DefinitionInfo, DefinitionInfoAndBoundSpan, FileReference, Node, Program, SourceFile, Symbol, TypeChecker } from "./_namespaces/ts";
/** @internal */
export declare function getDefinitionAtPosition(program: Program, sourceFile: SourceFile, position: number, searchOtherFilesOnly?: boolean, stopAtAlias?: boolean): readonly DefinitionInfo[] | undefined;
/** @internal */
export declare function getReferenceAtPosition(sourceFile: SourceFile, position: number, program: Program): {
    reference: FileReference;
    fileName: string;
    unverified: boolean;
    file?: SourceFile;
} | undefined;
/** @internal */
export declare function getTypeDefinitionAtPosition(typeChecker: TypeChecker, sourceFile: SourceFile, position: number): readonly DefinitionInfo[] | undefined;
/** @internal */
export declare function getDefinitionAndBoundSpan(program: Program, sourceFile: SourceFile, position: number): DefinitionInfoAndBoundSpan | undefined;
/**
 * Creates a DefinitionInfo from a Declaration, using the declaration's name if possible.
 *
 * @internal
 */
export declare function createDefinitionInfo(declaration: Declaration, checker: TypeChecker, symbol: Symbol, node: Node, unverified?: boolean, failedAliasResolution?: boolean): DefinitionInfo;
/** @internal */
export declare function findReferenceInPosition(refs: readonly FileReference[], pos: number): FileReference | undefined;
//# sourceMappingURL=goToDefinition.d.ts.map