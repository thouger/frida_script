import { DocumentPosition, DocumentPositionMapper, DocumentPositionMapperHost, LineAndCharacter, LineInfo, Program, SourceFileLike } from "./_namespaces/ts";
/** @internal */
export interface SourceMapper {
    toLineColumnOffset(fileName: string, position: number): LineAndCharacter;
    tryGetSourcePosition(info: DocumentPosition): DocumentPosition | undefined;
    tryGetGeneratedPosition(info: DocumentPosition): DocumentPosition | undefined;
    clearCache(): void;
}
/** @internal */
export interface SourceMapperHost {
    useCaseSensitiveFileNames(): boolean;
    getCurrentDirectory(): string;
    getProgram(): Program | undefined;
    fileExists?(path: string): boolean;
    readFile?(path: string, encoding?: string): string | undefined;
    getSourceFileLike?(fileName: string): SourceFileLike | undefined;
    getDocumentPositionMapper?(generatedFileName: string, sourceFileName?: string): DocumentPositionMapper | undefined;
    log(s: string): void;
}
/** @internal */
export declare function getSourceMapper(host: SourceMapperHost): SourceMapper;
/**
 * string | undefined to contents of map file to create DocumentPositionMapper from it
 * DocumentPositionMapper | false to give back cached DocumentPositionMapper
 *
 * @internal
 */
export type ReadMapFile = (mapFileName: string, mapFileNameFromDts: string | undefined) => string | undefined | DocumentPositionMapper | false;
/** @internal */
export declare function getDocumentPositionMapper(host: DocumentPositionMapperHost, generatedFileName: string, generatedFileLineInfo: LineInfo, readMapFile: ReadMapFile): DocumentPositionMapper | undefined;
//# sourceMappingURL=sourcemaps.d.ts.map