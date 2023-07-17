import { CancellationToken, HighlightSpan, Program, SourceFile } from "./_namespaces/ts";
export interface DocumentHighlights {
    fileName: string;
    highlightSpans: HighlightSpan[];
}
/** @internal */
export declare namespace DocumentHighlights {
    function getDocumentHighlights(program: Program, cancellationToken: CancellationToken, sourceFile: SourceFile, position: number, sourceFilesToSearch: readonly SourceFile[]): DocumentHighlights[] | undefined;
}
//# sourceMappingURL=documentHighlights.d.ts.map