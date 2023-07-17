import { FileTextChanges, formatting, GetCanonicalFileName, LanguageServiceHost, Program, SourceMapper, UserPreferences } from "./_namespaces/ts";
/** @internal */
export declare function getEditsForFileRename(program: Program, oldFileOrDirPath: string, newFileOrDirPath: string, host: LanguageServiceHost, formatContext: formatting.FormatContext, preferences: UserPreferences, sourceMapper: SourceMapper): readonly FileTextChanges[];
/**
 * If 'path' refers to an old directory, returns path in the new directory.
 *
 * @internal
 */
export type PathUpdater = (path: string) => string | undefined;
/** @internal */
export declare function getPathUpdater(oldFileOrDirPath: string, newFileOrDirPath: string, getCanonicalFileName: GetCanonicalFileName, sourceMapper: SourceMapper | undefined): PathUpdater;
//# sourceMappingURL=getEditsForFileRename.d.ts.map