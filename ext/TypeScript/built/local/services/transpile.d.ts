import { CompilerOptions, CustomTransformers, Diagnostic, MapLike } from "./_namespaces/ts";
export interface TranspileOptions {
    compilerOptions?: CompilerOptions;
    fileName?: string;
    reportDiagnostics?: boolean;
    moduleName?: string;
    renamedDependencies?: MapLike<string>;
    transformers?: CustomTransformers;
}
export interface TranspileOutput {
    outputText: string;
    diagnostics?: Diagnostic[];
    sourceMapText?: string;
}
export declare function transpileModule(input: string, transpileOptions: TranspileOptions): TranspileOutput;
export declare function transpile(input: string, compilerOptions?: CompilerOptions, fileName?: string, diagnostics?: Diagnostic[], moduleName?: string): string;
/**
 * JS users may pass in string values for enum compiler options (such as ModuleKind), so convert.
 *
 * @internal
 */
export declare function fixupCompilerOptions(options: CompilerOptions, diagnostics: Diagnostic[]): CompilerOptions;
//# sourceMappingURL=transpile.d.ts.map