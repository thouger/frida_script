import { TextSpan } from "./_namespaces/ts";
/** @internal */
export declare enum PatternMatchKind {
    exact = 0,
    prefix = 1,
    substring = 2,
    camelCase = 3
}
/** @internal */
export interface PatternMatch {
    kind: PatternMatchKind;
    isCaseSensitive: boolean;
}
/** @internal */
export interface PatternMatcher {
    getMatchForLastSegmentOfPattern(candidate: string): PatternMatch | undefined;
    getFullMatch(candidateContainers: readonly string[], candidate: string): PatternMatch | undefined;
    patternContainsDots: boolean;
}
/** @internal */
export declare function createPatternMatcher(pattern: string): PatternMatcher | undefined;
/** @internal */
export declare function breakIntoCharacterSpans(identifier: string): TextSpan[];
/** @internal */
export declare function breakIntoWordSpans(identifier: string): TextSpan[];
//# sourceMappingURL=patternMatcher.d.ts.map