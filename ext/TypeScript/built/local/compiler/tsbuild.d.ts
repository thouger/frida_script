import { Path, ResolvedConfigFileName } from "./_namespaces/ts";
/** @internal */
export declare enum UpToDateStatusType {
    Unbuildable = 0,
    UpToDate = 1,
    /**
     * The project appears out of date because its upstream inputs are newer than its outputs,
     * but all of its outputs are actually newer than the previous identical outputs of its (.d.ts) inputs.
     * This means we can Pseudo-build (just touch timestamps), as if we had actually built this project.
     */
    UpToDateWithUpstreamTypes = 2,
    /**
     * @deprecated
     * The project appears out of date because its upstream inputs are newer than its outputs,
     * but all of its outputs are actually newer than the previous identical outputs of its (.d.ts) inputs.
     * This means we can Pseudo-build (just manipulate outputs), as if we had actually built this project.
     */
    OutOfDateWithPrepend = 3,
    OutputMissing = 4,
    ErrorReadingFile = 5,
    OutOfDateWithSelf = 6,
    OutOfDateWithUpstream = 7,
    OutOfDateBuildInfo = 8,
    OutOfDateOptions = 9,
    OutOfDateRoots = 10,
    UpstreamOutOfDate = 11,
    UpstreamBlocked = 12,
    ComputingUpstream = 13,
    TsVersionOutputOfDate = 14,
    UpToDateWithInputFileText = 15,
    /**
     * Projects with no outputs (i.e. "solution" files)
     */
    ContainerOnly = 16,
    ForceBuild = 17
}
/** @internal */
export type UpToDateStatus = Status.Unbuildable | Status.UpToDate | Status.OutOfDateWithPrepend | Status.OutputMissing | Status.ErrorReadingFile | Status.OutOfDateWithSelf | Status.OutOfDateWithUpstream | Status.OutOfDateBuildInfo | Status.OutOfDateRoots | Status.UpstreamOutOfDate | Status.UpstreamBlocked | Status.ComputingUpstream | Status.TsVersionOutOfDate | Status.ContainerOnly | Status.ForceBuild;
/** @internal */
export declare namespace Status {
    /**
     * The project can't be built at all in its current state. For example,
     * its config file cannot be parsed, or it has a syntax error or missing file
     */
    interface Unbuildable {
        type: UpToDateStatusType.Unbuildable;
        reason: string;
    }
    /**
     * This project doesn't have any outputs, so "is it up to date" is a meaningless question.
     */
    interface ContainerOnly {
        type: UpToDateStatusType.ContainerOnly;
    }
    /**
     * The project is up to date with respect to its inputs.
     * We track what the newest input file is.
     */
    interface UpToDate {
        type: UpToDateStatusType.UpToDate | UpToDateStatusType.UpToDateWithUpstreamTypes | UpToDateStatusType.UpToDateWithInputFileText;
        newestInputFileTime?: Date;
        newestInputFileName?: string;
        oldestOutputFileName: string;
    }
    /**
     * @deprecated
     * The project is up to date with respect to its inputs except for prepend output changed (no declaration file change in prepend).
     */
    interface OutOfDateWithPrepend {
        type: UpToDateStatusType.OutOfDateWithPrepend;
        outOfDateOutputFileName: string;
        newerProjectName: string;
    }
    /**
     * One or more of the outputs of the project does not exist.
     */
    interface OutputMissing {
        type: UpToDateStatusType.OutputMissing;
        /**
         * The name of the first output file that didn't exist
         */
        missingOutputFileName: string;
    }
    /** Error reading file */
    interface ErrorReadingFile {
        type: UpToDateStatusType.ErrorReadingFile;
        fileName: string;
    }
    /**
     * One or more of the project's outputs is older than its newest input.
     */
    interface OutOfDateWithSelf {
        type: UpToDateStatusType.OutOfDateWithSelf;
        outOfDateOutputFileName: string;
        newerInputFileName: string;
    }
    /**
     * Buildinfo indicates that build is out of date
     */
    interface OutOfDateBuildInfo {
        type: UpToDateStatusType.OutOfDateBuildInfo | UpToDateStatusType.OutOfDateOptions;
        buildInfoFile: string;
    }
    interface OutOfDateRoots {
        type: UpToDateStatusType.OutOfDateRoots;
        buildInfoFile: string;
        inputFile: Path;
    }
    /**
     * This project depends on an out-of-date project, so shouldn't be built yet
     */
    interface UpstreamOutOfDate {
        type: UpToDateStatusType.UpstreamOutOfDate;
        upstreamProjectName: string;
    }
    /**
     * This project depends an upstream project with build errors
     */
    interface UpstreamBlocked {
        type: UpToDateStatusType.UpstreamBlocked;
        upstreamProjectName: string;
        upstreamProjectBlocked: boolean;
    }
    /**
     *  Computing status of upstream projects referenced
     */
    interface ComputingUpstream {
        type: UpToDateStatusType.ComputingUpstream;
    }
    interface TsVersionOutOfDate {
        type: UpToDateStatusType.TsVersionOutputOfDate;
        version: string;
    }
    /**
     * One or more of the project's outputs is older than the newest output of
     * an upstream project.
     */
    interface OutOfDateWithUpstream {
        type: UpToDateStatusType.OutOfDateWithUpstream;
        outOfDateOutputFileName: string;
        newerProjectName: string;
    }
    interface ForceBuild {
        type: UpToDateStatusType.ForceBuild;
    }
}
/** @internal */
export declare function resolveConfigFileProjectName(project: string): ResolvedConfigFileName;
//# sourceMappingURL=tsbuild.d.ts.map