import { Bundle, DiagnosticWithLocation, EmitHost, EmitResolver, Node, SourceFile, TransformationContext } from "../_namespaces/ts";
/** @internal */
export declare function getDeclarationDiagnostics(host: EmitHost, resolver: EmitResolver, file: SourceFile | undefined): DiagnosticWithLocation[] | undefined;
/** @internal */
export declare function isInternalDeclaration(node: Node, currentSourceFile: SourceFile): boolean | 0 | undefined;
/**
 * Transforms a ts file into a .d.ts file
 * This process requires type information, which is retrieved through the emit resolver. Because of this,
 * in many places this transformer assumes it will be operating on parse tree nodes directly.
 * This means that _no transforms should be allowed to occur before this one_.
 *
 * @internal
 */
export declare function transformDeclarations(context: TransformationContext): {
    (node: Bundle): Bundle;
    (node: SourceFile): SourceFile;
    (node: SourceFile | Bundle): SourceFile | Bundle;
};
//# sourceMappingURL=declarations.d.ts.map