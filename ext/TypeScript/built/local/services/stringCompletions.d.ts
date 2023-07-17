import { CancellationToken, CompilerOptions, CompletionEntryDetails, CompletionInfo, LanguageServiceHost, Node, Program, SourceFile, TypeChecker, UserPreferences } from "./_namespaces/ts";
import { Log } from "./_namespaces/ts.Completions";
/** @internal */
export declare function getStringLiteralCompletions(sourceFile: SourceFile, position: number, contextToken: Node | undefined, options: CompilerOptions, host: LanguageServiceHost, program: Program, log: Log, preferences: UserPreferences, includeSymbol: boolean): CompletionInfo | undefined;
/** @internal */
export declare function getStringLiteralCompletionDetails(name: string, sourceFile: SourceFile, position: number, contextToken: Node | undefined, checker: TypeChecker, options: CompilerOptions, host: LanguageServiceHost, cancellationToken: CancellationToken, preferences: UserPreferences): CompletionEntryDetails | undefined;
//# sourceMappingURL=stringCompletions.d.ts.map