import { DocumentPositionMapper, DocumentPositionMapperHost, EmitHost, RawSourceMap, SourceMapGenerator } from "./_namespaces/ts";
/** @internal */
export interface SourceMapGeneratorOptions {
    extendedDiagnostics?: boolean;
}
/** @internal */
export declare function createSourceMapGenerator(host: EmitHost, file: string, sourceRoot: string, sourcesDirectoryPath: string, generatorOptions: SourceMapGeneratorOptions): SourceMapGenerator;
/** @internal */
export declare const sourceMapCommentRegExpDontCareLineStart: RegExp;
/** @internal */
export declare const sourceMapCommentRegExp: RegExp;
/** @internal */
export declare const whitespaceOrMapCommentRegExp: RegExp;
/** @internal */
export interface LineInfo {
    getLineCount(): number;
    getLineText(line: number): string;
}
/** @internal */
export declare function getLineInfo(text: string, lineStarts: readonly number[]): LineInfo;
/**
 * Tries to find the sourceMappingURL comment at the end of a file.
 *
 * @internal
 */
export declare function tryGetSourceMappingURL(lineInfo: LineInfo): string | undefined;
/** @internal */
export declare function isRawSourceMap(x: any): x is RawSourceMap;
/** @internal */
export declare function tryParseRawSourceMap(text: string): RawSourceMap | undefined;
/** @internal */
export interface MappingsDecoder extends IterableIterator<Mapping> {
    readonly pos: number;
    readonly error: string | undefined;
    readonly state: Required<Mapping>;
}
/** @internal */
export interface Mapping {
    generatedLine: number;
    generatedCharacter: number;
    sourceIndex?: number;
    sourceLine?: number;
    sourceCharacter?: number;
    nameIndex?: number;
}
/** @internal */
export interface SourceMapping extends Mapping {
    sourceIndex: number;
    sourceLine: number;
    sourceCharacter: number;
}
/** @internal */
export declare function decodeMappings(mappings: string): MappingsDecoder;
/** @internal */
export declare function sameMapping<T extends Mapping>(left: T, right: T): boolean;
/** @internal */
export declare function isSourceMapping(mapping: Mapping): mapping is SourceMapping;
/** @internal */
export declare function createDocumentPositionMapper(host: DocumentPositionMapperHost, map: RawSourceMap, mapPath: string): DocumentPositionMapper;
/** @internal */
export declare const identitySourceMapConsumer: DocumentPositionMapper;
//# sourceMappingURL=sourcemap.d.ts.map