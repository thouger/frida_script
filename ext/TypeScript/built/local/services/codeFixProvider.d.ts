import { CodeActionCommand, CodeFixAction, CodeFixAllContext, CodeFixContext, CodeFixRegistration, CombinedCodeActions, DiagnosticOrDiagnosticAndArguments, DiagnosticWithLocation, FileTextChanges, TextChange, textChanges } from "./_namespaces/ts";
/** @internal */
export declare function createCodeFixActionWithoutFixAll(fixName: string, changes: FileTextChanges[], description: DiagnosticOrDiagnosticAndArguments): CodeFixAction;
/** @internal */
export declare function createCodeFixAction(fixName: string, changes: FileTextChanges[], description: DiagnosticOrDiagnosticAndArguments, fixId: {}, fixAllDescription: DiagnosticOrDiagnosticAndArguments, command?: CodeActionCommand): CodeFixAction;
/** @internal */
export declare function createCodeFixActionMaybeFixAll(fixName: string, changes: FileTextChanges[], description: DiagnosticOrDiagnosticAndArguments, fixId?: {}, fixAllDescription?: DiagnosticOrDiagnosticAndArguments, command?: CodeActionCommand): CodeFixAction;
/** @internal */
export declare function registerCodeFix(reg: CodeFixRegistration): void;
/** @internal */
export declare function getSupportedErrorCodes(): readonly string[];
/** @internal */
export declare function getFixes(context: CodeFixContext): readonly CodeFixAction[];
/** @internal */
export declare function getAllFixes(context: CodeFixAllContext): CombinedCodeActions;
/** @internal */
export declare function createCombinedCodeActions(changes: FileTextChanges[], commands?: CodeActionCommand[]): CombinedCodeActions;
/** @internal */
export declare function createFileTextChanges(fileName: string, textChanges: TextChange[]): FileTextChanges;
/** @internal */
export declare function codeFixAll(context: CodeFixAllContext, errorCodes: number[], use: (changes: textChanges.ChangeTracker, error: DiagnosticWithLocation, commands: CodeActionCommand[]) => void): CombinedCodeActions;
/** @internal */
export declare function eachDiagnostic(context: CodeFixAllContext, errorCodes: readonly number[], cb: (diag: DiagnosticWithLocation) => void): void;
//# sourceMappingURL=codeFixProvider.d.ts.map