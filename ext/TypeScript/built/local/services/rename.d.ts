import { Node, Program, RenameInfo, SourceFile, UserPreferences } from "./_namespaces/ts";
/** @internal */
export declare function getRenameInfo(program: Program, sourceFile: SourceFile, position: number, preferences: UserPreferences): RenameInfo;
/** @internal */
export declare function nodeIsEligibleForRename(node: Node): boolean;
//# sourceMappingURL=rename.d.ts.map