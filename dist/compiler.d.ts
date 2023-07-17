import TypedEmitter from "typed-emitter";
import ts from "../ext/typescript.js";
export declare function build(options: BuildOptions): string;
export declare function watch(options: WatchOptions): TypedEmitter<WatcherEvents>;
export interface Options {
    projectRoot: string;
    entrypoint: string;
    assets: Assets;
    system: ts.System;
    sourceMaps?: SourceMaps;
    compression?: Compression;
    onDiagnostic?(diagnostic: ts.Diagnostic): void;
}
export interface BuildOptions extends Options {
    onCompilerHostCreated?(compilerHost: ts.CompilerHost): void;
}
export interface WatchOptions extends Options {
    onWatchCompilerHostCreated?(compilerHost: ts.WatchCompilerHostOfFilesAndCompilerOptions<ts.EmitAndSemanticDiagnosticsBuilderProgram>): void;
}
export declare type SourceMaps = "included" | "omitted";
export declare type Compression = "none" | "terser";
export interface Assets {
    projectNodeModulesDir: string;
    compilerNodeModulesDir: string;
    shimDir: string;
    shims: Map<string, string>;
}
export declare type WatcherEvents = {
    compilationStarting: () => void;
    compilationFinished: () => void;
    bundleUpdated: (bundle: string) => void;
};
export declare function queryDefaultAssets(projectRoot: string, sys: ts.System): Assets;
export declare function makeDefaultCompilerOptions(): ts.CompilerOptions;
