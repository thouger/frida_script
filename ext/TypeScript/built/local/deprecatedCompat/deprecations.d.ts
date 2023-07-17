import { UnionToIntersection, Version } from "./_namespaces/ts";
/** @internal */
export interface DeprecationOptions {
    message?: string;
    error?: boolean;
    since?: Version | string;
    warnAfter?: Version | string;
    errorAfter?: Version | string;
    typeScriptVersion?: Version | string;
    name?: string;
}
/**
 * Defines a list of overloads by ordinal
 *
 * @internal
 */
export type OverloadDefinitions = {
    readonly [P in number]: (...args: any[]) => any;
};
/**
 * Extracts the ordinals from an set of overload definitions.
 *
 * @internal
 */
export type OverloadKeys<T extends OverloadDefinitions> = Extract<keyof T, number>;
/**
 * Extracts a union of the potential parameter lists for each overload.
 *
 * @internal
 */
export type OverloadParameters<T extends OverloadDefinitions> = Parameters<{
    [P in OverloadKeys<T>]: T[P];
}[OverloadKeys<T>]>;
/**
 * Constructs an intersection of each overload in a set of overload definitions.
 *
 * @internal
 */
export type OverloadFunction<T extends OverloadDefinitions> = UnionToIntersection<T[keyof T]>;
/**
 * Maps each ordinal in a set of overload definitions to a function that can be used to bind its arguments.
 *
 * @internal
 */
export type OverloadBinders<T extends OverloadDefinitions> = {
    [P in OverloadKeys<T>]: (args: OverloadParameters<T>) => boolean | undefined;
};
/**
 * Defines deprecations for specific overloads by ordinal.
 *
 * @internal
 */
export type OverloadDeprecations<T extends OverloadDefinitions> = {
    [P in OverloadKeys<T>]?: DeprecationOptions;
};
/** @internal */
export declare function createOverload<T extends OverloadDefinitions>(name: string, overloads: T, binder: OverloadBinders<T>, deprecations?: OverloadDeprecations<T>): UnionToIntersection<T[keyof T]>;
/** @internal */
export interface OverloadBuilder {
    overload<T extends OverloadDefinitions>(overloads: T): BindableOverloadBuilder<T>;
}
/** @internal */
export interface BindableOverloadBuilder<T extends OverloadDefinitions> {
    bind(binder: OverloadBinders<T>): BoundOverloadBuilder<T>;
}
/** @internal */
export interface FinishableOverloadBuilder<T extends OverloadDefinitions> {
    finish(): OverloadFunction<T>;
}
/** @internal */
export interface BoundOverloadBuilder<T extends OverloadDefinitions> extends FinishableOverloadBuilder<T> {
    deprecate(deprecations: OverloadDeprecations<T>): FinishableOverloadBuilder<T>;
}
/** @internal */
export declare function buildOverload(name: string): OverloadBuilder;
//# sourceMappingURL=deprecations.d.ts.map