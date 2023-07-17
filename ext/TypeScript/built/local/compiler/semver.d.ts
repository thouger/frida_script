import { Comparison } from "./_namespaces/ts";
/**
 * Describes a precise semantic version number, https://semver.org
 *
 * @internal
 */
export declare class Version {
    static readonly zero: Version;
    readonly major: number;
    readonly minor: number;
    readonly patch: number;
    readonly prerelease: readonly string[];
    readonly build: readonly string[];
    constructor(text: string);
    constructor(major: number, minor?: number, patch?: number, prerelease?: string | readonly string[], build?: string | readonly string[]);
    static tryParse(text: string): Version | undefined;
    compareTo(other: Version | undefined): Comparison;
    increment(field: "major" | "minor" | "patch"): Version;
    with(fields: {
        major?: number;
        minor?: number;
        patch?: number;
        prerelease?: string | readonly string[];
        build?: string | readonly string[];
    }): Version;
    toString(): string;
}
/**
 * Describes a semantic version range, per https://github.com/npm/node-semver#ranges
 *
 * @internal
 */
export declare class VersionRange {
    private _alternatives;
    constructor(spec: string);
    static tryParse(text: string): VersionRange | undefined;
    /**
     * Tests whether a version matches the range. This is equivalent to `satisfies(version, range, { includePrerelease: true })`.
     * in `node-semver`.
     */
    test(version: Version | string): boolean;
    toString(): string;
}
//# sourceMappingURL=semver.d.ts.map