import { AnyImportOrRequireStatement, BinaryExpression, BindingElement, ClassDeclaration, EnumDeclaration, ExpressionStatement, ExternalModuleReference, FunctionDeclaration, GetCanonicalFileName, Identifier, ImportDeclaration, ImportEqualsDeclaration, InterfaceDeclaration, LanguageServiceHost, ModuleDeclaration, Node, Program, PropertyAccessExpression, QuotePreference, RefactorContext, RequireOrImportCall, SourceFile, Statement, StringLiteralLike, Symbol, textChanges, TypeAliasDeclaration, TypeChecker, VariableDeclaration, VariableDeclarationList, VariableStatement } from "../_namespaces/ts";
/** @internal */
export declare function addNewFileToTsconfig(program: Program, changes: textChanges.ChangeTracker, oldFileName: string, newFileNameWithExtension: string, getCanonicalFileName: GetCanonicalFileName): void;
/** @internal */
export declare function deleteMovedStatements(sourceFile: SourceFile, moved: readonly StatementRange[], changes: textChanges.ChangeTracker): void;
/** @internal */
export declare function deleteUnusedOldImports(oldFile: SourceFile, toMove: readonly Statement[], changes: textChanges.ChangeTracker, toDelete: Set<Symbol>, checker: TypeChecker): void;
/** @internal */
export declare function updateImportsInOtherFiles(changes: textChanges.ChangeTracker, program: Program, host: LanguageServiceHost, oldFile: SourceFile, movedSymbols: Set<Symbol>, targetFileName: string, quotePreference: QuotePreference): void;
/** @internal */
export declare function moduleSpecifierFromImport(i: SupportedImport): StringLiteralLike;
/** @internal */
export declare function forEachImportInStatement(statement: Statement, cb: (importNode: SupportedImport) => void): void;
/** @internal */
export type SupportedImport = ImportDeclaration & {
    moduleSpecifier: StringLiteralLike;
} | ImportEqualsDeclaration & {
    moduleReference: ExternalModuleReference & {
        expression: StringLiteralLike;
    };
} | VariableDeclaration & {
    initializer: RequireOrImportCall;
};
/** @internal */
export type SupportedImportStatement = ImportDeclaration | ImportEqualsDeclaration | VariableStatement;
/** @internal */
export declare function createOldFileImportsFromTargetFile(sourceFile: SourceFile, targetFileNeedExport: Set<Symbol>, targetFileNameWithExtension: string, program: Program, host: LanguageServiceHost, useEs6Imports: boolean, quotePreference: QuotePreference): AnyImportOrRequireStatement | undefined;
/** @internal */
export declare function makeImportOrRequire(sourceFile: SourceFile, defaultImport: Identifier | undefined, imports: readonly string[], targetFileNameWithExtension: string, program: Program, host: LanguageServiceHost, useEs6Imports: boolean, quotePreference: QuotePreference): AnyImportOrRequireStatement | undefined;
/** @internal */
export declare function addExports(sourceFile: SourceFile, toMove: readonly Statement[], needExport: Set<Symbol>, useEs6Exports: boolean): readonly Statement[];
/** @internal */
export declare function deleteUnusedImports(sourceFile: SourceFile, importDecl: SupportedImport, changes: textChanges.ChangeTracker, isUnused: (name: Identifier) => boolean): void;
/** @internal */
export type TopLevelDeclarationStatement = NonVariableTopLevelDeclaration | VariableStatement;
/** @internal */
export declare function filterImport(i: SupportedImport, moduleSpecifier: StringLiteralLike, keep: (name: Identifier) => boolean): SupportedImportStatement | undefined;
/** @internal */
export declare function nameOfTopLevelDeclaration(d: TopLevelDeclaration): Identifier | undefined;
/** @internal */
export declare function getTopLevelDeclarationStatement(d: TopLevelDeclaration): TopLevelDeclarationStatement;
/** @internal */
export declare function addExportToChanges(sourceFile: SourceFile, decl: TopLevelDeclarationStatement, name: Identifier, changes: textChanges.ChangeTracker, useEs6Exports: boolean): void;
/** @internal */
export interface ToMove {
    readonly all: readonly Statement[];
    readonly ranges: readonly StatementRange[];
}
/** @internal */
export interface StatementRange {
    readonly first: Statement;
    readonly afterLast: Statement | undefined;
}
/** @internal */
export interface UsageInfo {
    readonly movedSymbols: Set<Symbol>;
    readonly targetFileImportsFromOldFile: Set<Symbol>;
    readonly oldFileImportsFromTargetFile: Set<Symbol>;
    readonly oldImportsNeededByTargetFile: Map<Symbol, boolean>;
    readonly unusedImportsFromOldFile: Set<Symbol>;
}
/** @internal */
export type TopLevelExpressionStatement = ExpressionStatement & {
    expression: BinaryExpression & {
        left: PropertyAccessExpression;
    };
};
/** @internal */
export type NonVariableTopLevelDeclaration = FunctionDeclaration | ClassDeclaration | EnumDeclaration | TypeAliasDeclaration | InterfaceDeclaration | ModuleDeclaration | TopLevelExpressionStatement | ImportEqualsDeclaration;
/** @internal */
export interface TopLevelVariableDeclaration extends VariableDeclaration {
    parent: VariableDeclarationList & {
        parent: VariableStatement;
    };
}
/** @internal */
export type TopLevelDeclaration = NonVariableTopLevelDeclaration | TopLevelVariableDeclaration | BindingElement;
/** @internal */
export declare function createNewFileName(oldFile: SourceFile, program: Program, context: RefactorContext, host: LanguageServiceHost): string;
/** @internal */
export declare function getStatementsToMove(context: RefactorContext): ToMove | undefined;
/** @internal */
export declare function getUsageInfo(oldFile: SourceFile, toMove: readonly Statement[], checker: TypeChecker): UsageInfo;
/** @internal */
export declare function isTopLevelDeclaration(node: Node): node is TopLevelDeclaration;
//# sourceMappingURL=moveToFile.d.ts.map