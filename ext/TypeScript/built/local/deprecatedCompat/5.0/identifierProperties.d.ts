declare module "../../compiler/types" {
    interface Identifier {
        /** @deprecated Use `idKeyword(identifier)` instead. */
        readonly originalKeywordKind?: SyntaxKind;
        /** @deprecated Use `.parent` or the surrounding context to determine this instead. */
        readonly isInJSDocNamespace?: boolean;
    }
}
export {};
//# sourceMappingURL=identifierProperties.d.ts.map