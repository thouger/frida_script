import { HasDecorators, HasModifiers, Node, TextRange } from "../_namespaces/ts";
export declare function setTextRange<T extends TextRange>(range: T, location: TextRange | undefined): T;
export declare function canHaveModifiers(node: Node): node is HasModifiers;
export declare function canHaveDecorators(node: Node): node is HasDecorators;
//# sourceMappingURL=utilitiesPublic.d.ts.map