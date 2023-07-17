import { CallExpression, Identifier, SourceFile, TaggedTemplateExpression, TransformationContext, Visitor } from "../_namespaces/ts";
/** @internal */
export declare enum ProcessLevel {
    LiftRestriction = 0,
    All = 1
}
/** @internal */
export declare function processTaggedTemplateExpression(context: TransformationContext, node: TaggedTemplateExpression, visitor: Visitor, currentSourceFile: SourceFile, recordTaggedTemplateString: (temp: Identifier) => void, level: ProcessLevel): CallExpression | TaggedTemplateExpression;
//# sourceMappingURL=taggedTemplate.d.ts.map