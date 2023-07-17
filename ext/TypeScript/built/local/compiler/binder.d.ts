import { CompilerOptions, Expression, ModuleDeclaration, SourceFile } from "./_namespaces/ts";
/** @internal */
export declare const enum ModuleInstanceState {
    NonInstantiated = 0,
    Instantiated = 1,
    ConstEnumOnly = 2
}
/** @internal */
export declare function getModuleInstanceState(node: ModuleDeclaration, visited?: Map<number, ModuleInstanceState | undefined>): ModuleInstanceState;
/** @internal */
export declare function bindSourceFile(file: SourceFile, options: CompilerOptions): void;
/** @internal */
export declare function isExportsOrModuleExportsOrAlias(sourceFile: SourceFile, node: Expression): boolean;
//# sourceMappingURL=binder.d.ts.map