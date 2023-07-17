/*!

*****************************************************************************
Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED
WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache Version 2.0 License for specific language governing permissions
and limitations under the License.
*****************************************************************************

*/
import { Buffer } from "buffer";
import _crypto from "crypto";
import _fs from "fs";
import _os from "os";
import _path from "path";
import ts from "../../ext/typescript.js";
var FileWatcherEventKind;
(function (FileWatcherEventKind) {
    FileWatcherEventKind[FileWatcherEventKind["Created"] = 0] = "Created";
    FileWatcherEventKind[FileWatcherEventKind["Changed"] = 1] = "Changed";
    FileWatcherEventKind[FileWatcherEventKind["Deleted"] = 2] = "Deleted";
})(FileWatcherEventKind || (FileWatcherEventKind = {}));
// NodeJS detects "\uFEFF" at the start of the string and *replaces* it with the actual
// byte order mark from the specified encoding. Using any other byte order mark does
// not actually work.
const byteOrderMarkIndicator = "\uFEFF";
const tsPriv = ts;
const { combinePaths, containsPath, createGetCanonicalFileName, createSystemWatchFunctions, emptyFileSystemEntries, generateDjb2Hash, getRelativePathToDirectoryOrUrl, getRootLength, matchFiles, memoize, normalizeSlashes, some, } = tsPriv;
export function getNodeSystem() {
    let nodeSystem;
    const selfPath = import.meta.url.substring((process.platform === "win32") ? 8 : 7);
    const systemDir = _path.dirname(selfPath);
    const distDir = _path.dirname(systemDir);
    const pkgDir = _path.dirname(distDir);
    const typescriptJsPath = _path.join(pkgDir, "ext", "typescript.js");
    const nativePattern = /^native |^\([^)]+\)$|^(internal[\\/]|[a-zA-Z0-9_\s]+(\.js)?$)/;
    const isLinuxOrMacOs = process.platform === "linux" || process.platform === "darwin";
    const platform = _os.platform();
    const useCaseSensitiveFileNames = isFileSystemCaseSensitive();
    const fsRealpath = !!_fs.realpathSync.native ? process.platform === "win32" ? fsRealPathHandlingLongPath : _fs.realpathSync.native : _fs.realpathSync;
    const fsSupportsRecursiveFsWatch = process.platform === "win32" || process.platform === "darwin";
    const getCurrentDirectory = memoize(() => process.cwd());
    const { watchFile, watchDirectory } = createSystemWatchFunctions({
        pollingWatchFileWorker: fsWatchFileWorker,
        getModifiedTime,
        setTimeout,
        clearTimeout,
        fsWatchWorker,
        useCaseSensitiveFileNames,
        getCurrentDirectory,
        fileSystemEntryExists,
        // Node 4.0 `fs.watch` function supports the "recursive" option on both OSX and Windows
        // (ref: https://github.com/nodejs/node/pull/2649 and https://github.com/Microsoft/TypeScript/issues/4643)
        fsSupportsRecursiveFsWatch,
        getAccessibleSortedChildDirectories: (path) => getAccessibleFileSystemEntries(path).directories,
        realpath,
        tscWatchFile: process.env.TSC_WATCHFILE,
        useNonPollingWatchers: process.env.TSC_NONPOLLING_WATCHER,
        tscWatchDirectory: process.env.TSC_WATCHDIRECTORY,
        defaultWatchFileKind: () => nodeSystem.defaultWatchFileKind?.(),
        inodeWatching: isLinuxOrMacOs,
        sysLog: tsPriv.sysLog,
    });
    nodeSystem = {
        args: process.argv.slice(2),
        newLine: _os.EOL,
        useCaseSensitiveFileNames,
        write(s) {
            process.stdout.write(s);
        },
        getWidthOfTerminal() {
            return process.stdout.columns;
        },
        writeOutputIsTTY() {
            return process.stdout.isTTY;
        },
        readFile,
        writeFile,
        watchFile,
        watchDirectory,
        resolvePath: path => _path.resolve(path),
        fileExists,
        directoryExists,
        createDirectory(directoryName) {
            if (!nodeSystem.directoryExists(directoryName)) {
                // Wrapped in a try-catch to prevent crashing if we are in a race
                // with another copy of ourselves to create the same directory
                try {
                    _fs.mkdirSync(directoryName);
                }
                catch (e) {
                    if (e.code !== "EEXIST") {
                        // Failed for some other reason (access denied?); still throw
                        throw e;
                    }
                }
            }
        },
        getExecutingFilePath() {
            return typescriptJsPath;
        },
        getCurrentDirectory,
        getDirectories,
        readDirectory,
        getModifiedTime,
        setModifiedTime,
        deleteFile,
        createHash: _crypto ? createSHA256Hash : generateDjb2Hash,
        createSHA256Hash: _crypto ? createSHA256Hash : undefined,
        getMemoryUsage() {
            if (global.gc) {
                global.gc();
            }
            return process.memoryUsage().heapUsed;
        },
        getFileSize(path) {
            try {
                const stat = statSync(path);
                if (stat?.isFile()) {
                    return stat.size;
                }
            }
            catch { /*ignore*/ }
            return 0;
        },
        exit(exitCode) {
            process.exit(exitCode);
        },
        realpath,
        setTimeout,
        clearTimeout,
        clearScreen: () => {
            process.stdout.write("\x1Bc");
        },
        base64decode: input => bufferFrom(input, "base64").toString("utf8"),
        base64encode: input => bufferFrom(input).toString("base64"),
    };
    Object.assign(nodeSystem, {
        getEnvironmentVariable(name) {
            return process.env[name] || "";
        },
        debugMode: !!process.env.NODE_INSPECTOR_IPC || !!process.env.VSCODE_INSPECTOR_OPTIONS || some(process.execArgv, (arg) => /^--(inspect|debug)(-brk)?(=\d+)?$/i.test(arg)),
        setBlocking: () => {
            process.stdout?._handle?.setBlocking?.(true);
        },
        bufferFrom,
    });
    return nodeSystem;
    /**
     * `throwIfNoEntry` was added so recently that it's not in the node types.
     * This helper encapsulates the mitigating usage of `any`.
     * See https://github.com/nodejs/node/pull/33716
     */
    function statSync(path) {
        // throwIfNoEntry will be ignored by older versions of node
        return _fs.statSync(path, { throwIfNoEntry: false });
    }
    /**
     * Strips non-TS paths from the profile, so users with private projects shouldn't
     * need to worry about leaking paths by submitting a cpu profile to us
     */
    function cleanupPaths(profile) {
        let externalFileCounter = 0;
        const remappedPaths = new Map();
        const normalizedDir = normalizeSlashes(__dirname);
        // Windows rooted dir names need an extra `/` prepended to be valid file:/// urls
        const fileUrlRoot = `file://${getRootLength(normalizedDir) === 1 ? "" : "/"}${normalizedDir}`;
        for (const node of profile.nodes) {
            if (node.callFrame.url) {
                const url = normalizeSlashes(node.callFrame.url);
                if (containsPath(fileUrlRoot, url, useCaseSensitiveFileNames)) {
                    node.callFrame.url = getRelativePathToDirectoryOrUrl(fileUrlRoot, url, fileUrlRoot, createGetCanonicalFileName(useCaseSensitiveFileNames), /*isAbsolutePathAnUrl*/ true);
                }
                else if (!nativePattern.test(url)) {
                    node.callFrame.url = (remappedPaths.has(url) ? remappedPaths : remappedPaths.set(url, `external${externalFileCounter}.js`)).get(url);
                    externalFileCounter++;
                }
            }
        }
        return profile;
    }
    function bufferFrom(input, encoding) {
        // See https://github.com/Microsoft/TypeScript/issues/25652
        return Buffer.from && Buffer.from !== Int8Array.from
            ? Buffer.from(input, encoding)
            : new Buffer(input, encoding);
    }
    function isFileSystemCaseSensitive() {
        // win32\win64 are case insensitive platforms
        if (platform === "win32" || platform === "win64") {
            return false;
        }
        // If this file exists under a different case, we must be case-insensitve.
        return !fileExists(swapCase(typescriptJsPath));
    }
    /** Convert all lowercase chars to uppercase, and vice-versa */
    function swapCase(s) {
        return s.replace(/\w/g, (ch) => {
            const up = ch.toUpperCase();
            return ch === up ? ch.toLowerCase() : up;
        });
    }
    function fsWatchFileWorker(fileName, callback, pollingInterval) {
        _fs.watchFile(fileName, { persistent: true, interval: pollingInterval }, fileChanged);
        let eventKind;
        return {
            close: () => _fs.unwatchFile(fileName, fileChanged)
        };
        function fileChanged(curr, prev) {
            // previous event kind check is to ensure we recongnize the file as previously also missing when it is restored or renamed twice (that is it disappears and reappears)
            // In such case, prevTime returned is same as prev time of event when file was deleted as per node documentation
            const isPreviouslyDeleted = +prev.mtime === 0 || eventKind === FileWatcherEventKind.Deleted;
            if (+curr.mtime === 0) {
                if (isPreviouslyDeleted) {
                    // Already deleted file, no need to callback again
                    return;
                }
                eventKind = FileWatcherEventKind.Deleted;
            }
            else if (isPreviouslyDeleted) {
                eventKind = FileWatcherEventKind.Created;
            }
            // If there is no change in modified time, ignore the event
            else if (+curr.mtime === +prev.mtime) {
                return;
            }
            else {
                // File changed
                eventKind = FileWatcherEventKind.Changed;
            }
            callback(fileName, eventKind, curr.mtime);
        }
    }
    function fsWatchWorker(fileOrDirectory, recursive, callback) {
        // Node 4.0 `fs.watch` function supports the "recursive" option on both OSX and Windows
        // (ref: https://github.com/nodejs/node/pull/2649 and https://github.com/Microsoft/TypeScript/issues/4643)
        return _fs.watch(fileOrDirectory, fsSupportsRecursiveFsWatch ?
            { persistent: true, recursive: !!recursive } : { persistent: true }, callback);
    }
    function readFileWorker(fileName, _encoding) {
        let buffer;
        try {
            buffer = _fs.readFileSync(fileName);
        }
        catch (e) {
            return undefined;
        }
        let len = buffer.length;
        if (len >= 2 && buffer[0] === 0xFE && buffer[1] === 0xFF) {
            // Big endian UTF-16 byte order mark detected. Since big endian is not supported by node.js,
            // flip all byte pairs and treat as little endian.
            len &= ~1; // Round down to a multiple of 2
            for (let i = 0; i < len; i += 2) {
                const temp = buffer[i];
                buffer[i] = buffer[i + 1];
                buffer[i + 1] = temp;
            }
            return buffer.toString("utf16le", 2);
        }
        if (len >= 2 && buffer[0] === 0xFF && buffer[1] === 0xFE) {
            // Little endian UTF-16 byte order mark detected
            return buffer.toString("utf16le", 2);
        }
        if (len >= 3 && buffer[0] === 0xEF && buffer[1] === 0xBB && buffer[2] === 0xBF) {
            // UTF-8 byte order mark detected
            return buffer.toString("utf8", 3);
        }
        // Default is UTF-8 with no byte order mark
        return buffer.toString("utf8");
    }
    function readFile(fileName, _encoding) {
        return readFileWorker(fileName, _encoding);
    }
    function writeFile(fileName, data, writeByteOrderMark) {
        // If a BOM is required, emit one
        if (writeByteOrderMark) {
            data = byteOrderMarkIndicator + data;
        }
        let fd;
        try {
            fd = _fs.openSync(fileName, "w");
            _fs.writeSync(fd, data, /*position*/ undefined, "utf8");
        }
        finally {
            if (fd !== undefined) {
                _fs.closeSync(fd);
            }
        }
    }
    function getAccessibleFileSystemEntries(path) {
        try {
            const entries = _fs.readdirSync(path || ".", { withFileTypes: true });
            const files = [];
            const directories = [];
            for (const dirent of entries) {
                // withFileTypes is not supported before Node 10.10.
                const entry = typeof dirent === "string" ? dirent : dirent.name;
                // This is necessary because on some file system node fails to exclude
                // "." and "..". See https://github.com/nodejs/node/issues/4002
                if (entry === "." || entry === "..") {
                    continue;
                }
                let stat;
                if (typeof dirent === "string" || dirent.isSymbolicLink()) {
                    const name = combinePaths(path, entry);
                    try {
                        stat = statSync(name);
                        if (!stat) {
                            continue;
                        }
                    }
                    catch (e) {
                        continue;
                    }
                }
                else {
                    stat = dirent;
                }
                if (stat.isFile()) {
                    files.push(entry);
                }
                else if (stat.isDirectory()) {
                    directories.push(entry);
                }
            }
            files.sort();
            directories.sort();
            return { files, directories };
        }
        catch (e) {
            return emptyFileSystemEntries;
        }
    }
    function readDirectory(path, extensions, excludes, includes, depth) {
        return matchFiles(path, extensions, excludes, includes, useCaseSensitiveFileNames, process.cwd(), depth, getAccessibleFileSystemEntries, realpath);
    }
    function fileSystemEntryExists(path, entryKind) {
        // Since the error thrown by fs.statSync isn't used, we can avoid collecting a stack trace to improve
        // the CPU time performance.
        const originalStackTraceLimit = Error.stackTraceLimit;
        Error.stackTraceLimit = 0;
        try {
            const stat = statSync(path);
            if (!stat) {
                return false;
            }
            switch (entryKind) {
                case 0 /* FileSystemEntryKind.File */: return stat.isFile();
                case 1 /* FileSystemEntryKind.Directory */: return stat.isDirectory();
                default: return false;
            }
        }
        catch (e) {
            return false;
        }
        finally {
            Error.stackTraceLimit = originalStackTraceLimit;
        }
    }
    function fileExists(path) {
        return fileSystemEntryExists(path, 0 /* FileSystemEntryKind.File */);
    }
    function directoryExists(path) {
        return fileSystemEntryExists(path, 1 /* FileSystemEntryKind.Directory */);
    }
    function getDirectories(path) {
        return getAccessibleFileSystemEntries(path).directories.slice();
    }
    function fsRealPathHandlingLongPath(path) {
        return path.length < 260 ? _fs.realpathSync.native(path) : _fs.realpathSync(path);
    }
    function realpath(path) {
        try {
            return fsRealpath(path);
        }
        catch {
            return path;
        }
    }
    function getModifiedTime(path) {
        // Since the error thrown by fs.statSync isn't used, we can avoid collecting a stack trace to improve
        // the CPU time performance.
        const originalStackTraceLimit = Error.stackTraceLimit;
        Error.stackTraceLimit = 0;
        try {
            return statSync(path)?.mtime;
        }
        catch (e) {
            return undefined;
        }
        finally {
            Error.stackTraceLimit = originalStackTraceLimit;
        }
    }
    function setModifiedTime(path, time) {
        try {
            _fs.utimesSync(path, time, time);
        }
        catch (e) {
            return;
        }
    }
    function deleteFile(path) {
        try {
            return _fs.unlinkSync(path);
        }
        catch (e) {
            return;
        }
    }
    function createSHA256Hash(data) {
        const hash = _crypto.createHash("sha256");
        hash.update(data);
        return hash.digest("hex");
    }
}
var PollingInterval;
(function (PollingInterval) {
    PollingInterval[PollingInterval["High"] = 2000] = "High";
    PollingInterval[PollingInterval["Medium"] = 500] = "Medium";
    PollingInterval[PollingInterval["Low"] = 250] = "Low";
})(PollingInterval || (PollingInterval = {}));
