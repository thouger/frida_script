import { DeprecationOptions } from "./_namespaces/ts";
export declare let enableDeprecationWarnings: boolean;
export declare function setEnableDeprecationWarnings(value: boolean): void;
export declare function createDeprecation(name: string, options: DeprecationOptions & {
    error: true;
}): () => never;
export declare function createDeprecation(name: string, options?: DeprecationOptions): () => void;
export declare function deprecate<F extends (...args: any[]) => any>(func: F, options?: DeprecationOptions): F;
//# sourceMappingURL=deprecate.d.ts.map