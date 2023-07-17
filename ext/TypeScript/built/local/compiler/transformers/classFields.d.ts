import { Bundle, SourceFile, TransformationContext } from "../_namespaces/ts";
/**
 * Transforms ECMAScript Class Syntax.
 * TypeScript parameter property syntax is transformed in the TypeScript transformer.
 * For now, this transforms public field declarations using TypeScript class semantics,
 * where declarations are elided and initializers are transformed as assignments in the constructor.
 * When --useDefineForClassFields is on, this transforms to ECMAScript semantics, with Object.defineProperty.
 *
 * @internal
 */
export declare function transformClassFields(context: TransformationContext): (x: SourceFile | Bundle) => SourceFile | Bundle;
//# sourceMappingURL=classFields.d.ts.map