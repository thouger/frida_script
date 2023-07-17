import { Buffer } from "buffer";
import * as crosspath from "@frida/crosspath";
import EventEmitter from "events";
import process from "process";
import { check as checkIdentifier } from "@frida/reserved-words";
import { minify } from "@frida/terser";
import ts from "../ext/typescript.js";
const compilerRoot = detectCompilerRoot();
const sourceTransformers = {
    after: [
        useStrictRemovalTransformer(),
    ]
};
export function build(options) {
    options = normalizeOptions(options);
    const entrypoint = deriveEntrypoint(options);
    const outputOptions = makeOutputOptions(options);
    const { projectRoot, assets, system, onDiagnostic } = options;
    const compilerOpts = makeCompilerOptions(projectRoot, system, outputOptions);
    const compilerHost = ts.createIncrementalCompilerHost(compilerOpts, system);
    options.onCompilerHostCreated?.(compilerHost);
    const program = ts.createProgram({
        rootNames: [entrypoint.input],
        options: compilerOpts,
        host: compilerHost
    });
    const preEmitDiagnostics = ts.getPreEmitDiagnostics(program);
    if (onDiagnostic !== undefined) {
        for (const diagnostic of preEmitDiagnostics) {
            onDiagnostic(diagnostic);
        }
    }
    if (preEmitDiagnostics.some(({ category }) => category === ts.DiagnosticCategory.Error)) {
        throw new Error("compilation failed");
    }
    const bundler = createBundler(entrypoint, projectRoot, assets, system, outputOptions);
    const emitResult = program.emit(undefined, undefined, undefined, undefined, sourceTransformers);
    if (onDiagnostic !== undefined) {
        for (const diagnostic of emitResult.diagnostics) {
            onDiagnostic(diagnostic);
        }
    }
    if (emitResult.emitSkipped || emitResult.diagnostics.some(({ category }) => category === ts.DiagnosticCategory.Error)) {
        throw new Error("compilation failed");
    }
    return bundler.bundle(program);
}
export function watch(options) {
    options = normalizeOptions(options);
    const entrypoint = deriveEntrypoint(options);
    const outputOptions = makeOutputOptions(options);
    const { projectRoot, assets, system, onDiagnostic } = options;
    const events = new EventEmitter();
    const origCreateProgram = ts.createEmitAndSemanticDiagnosticsBuilderProgram;
    const createProgram = (...args) => {
        events.emit("compilationStarting");
        const program = origCreateProgram(...args);
        if (onDiagnostic !== undefined) {
            const preEmitDiagnostics = ts.getPreEmitDiagnostics(program.getProgram());
            for (const diagnostic of preEmitDiagnostics) {
                onDiagnostic(diagnostic);
            }
        }
        const origEmit = program.emit;
        program.emit = (targetSourceFile, writeFile, cancellationToken, emitOnlyDtsFiles, customTransformers) => {
            const emitResult = origEmit(targetSourceFile, writeFile, cancellationToken, emitOnlyDtsFiles, sourceTransformers);
            if (onDiagnostic !== undefined) {
                for (const diagnostic of emitResult.diagnostics) {
                    onDiagnostic(diagnostic);
                }
            }
            return emitResult;
        };
        return program;
    };
    const compilerOpts = makeCompilerOptions(projectRoot, system, outputOptions);
    const compilerHost = ts.createWatchCompilerHost([entrypoint.input], compilerOpts, system, createProgram);
    options.onWatchCompilerHostCreated?.(compilerHost);
    let state = "dirty";
    let timer = null;
    const bundler = createBundler(entrypoint, projectRoot, assets, system, outputOptions);
    bundler.events.on("externalSourceFileAdded", file => {
        compilerHost.watchFile(file.fileName, () => {
            state = "dirty";
            bundler.invalidate(file.fileName);
            if (timer !== null) {
                return;
            }
            timer = setTimeout(() => {
                timer = null;
                rebundle();
            }, 250);
        });
    });
    const origPostProgramCreate = compilerHost.afterProgramCreate;
    compilerHost.afterProgramCreate = program => {
        origPostProgramCreate(program);
        process.nextTick(rebundle);
    };
    let watchProgram;
    process.nextTick(() => {
        watchProgram = ts.createWatchProgram(compilerHost);
    });
    let previousBundle = null;
    function rebundle() {
        state = "clean";
        try {
            const bundle = bundler.bundle(watchProgram.getProgram().getProgram());
            if (bundle !== previousBundle) {
                events.emit("bundleUpdated", bundle);
                previousBundle = bundle;
            }
        }
        catch (e) {
            console.error("Failed to bundle:", e);
        }
        events.emit("compilationFinished");
    }
    return events;
}
function normalizeOptions(options) {
    return Object.assign({}, options, {
        projectRoot: crosspath.ensurePosix(options.projectRoot),
        entrypoint: crosspath.ensurePosix(options.entrypoint),
    });
}
function deriveEntrypoint(options) {
    const { projectRoot, entrypoint } = options;
    const input = crosspath.isAbsolute(entrypoint) ? entrypoint : crosspath.join(projectRoot, entrypoint);
    if (!input.startsWith(projectRoot)) {
        throw new Error("entrypoint must be inside the project root");
    }
    let output = input.substring(projectRoot.length);
    if (output.endsWith(".ts")) {
        output = output.substring(0, output.length - 2) + "js";
    }
    return { input, output };
}
function makeOutputOptions(options) {
    const { sourceMaps = "included", compression = "none", } = options;
    return { sourceMaps, compression };
}
export function queryDefaultAssets(projectRoot, sys) {
    const projectNodeModulesDir = crosspath.join(crosspath.ensurePosix(projectRoot), "node_modules");
    const compilerNodeModulesDir = crosspath.join(compilerRoot, "node_modules");
    let shimDir;
    if (sys.directoryExists(crosspath.join(compilerNodeModulesDir, "@frida"))) {
        shimDir = compilerNodeModulesDir;
    }
    else if (sys.directoryExists(crosspath.join(projectNodeModulesDir, "@frida"))) {
        shimDir = projectNodeModulesDir;
    }
    else {
        const compilerParent = crosspath.dirname(compilerRoot);
        if (crosspath.basename(compilerParent) === "node_modules" &&
            sys.directoryExists(crosspath.join(compilerParent, "@frida"))) {
            shimDir = compilerParent;
        }
        else {
            throw new Error("Unable to detect shim directory; please file a bug");
        }
    }
    const shims = new Map([
        ["assert", crosspath.join(shimDir, "@frida", "assert")],
        ["base64-js", crosspath.join(shimDir, "@frida", "base64-js")],
        ["buffer", crosspath.join(shimDir, "@frida", "buffer")],
        ["diagnostics_channel", crosspath.join(shimDir, "@frida", "diagnostics_channel")],
        ["events", crosspath.join(shimDir, "@frida", "events")],
        ["fs", crosspath.join(shimDir, "frida-fs")],
        ["http", crosspath.join(shimDir, "@frida", "http")],
        ["https", crosspath.join(shimDir, "@frida", "https")],
        ["http-parser-js", crosspath.join(shimDir, "@frida", "http-parser-js")],
        ["ieee754", crosspath.join(shimDir, "@frida", "ieee754")],
        ["net", crosspath.join(shimDir, "@frida", "net")],
        ["os", crosspath.join(shimDir, "@frida", "os")],
        ["path", crosspath.join(shimDir, "@frida", "path")],
        ["process", crosspath.join(shimDir, "@frida", "process")],
        ["punycode", crosspath.join(shimDir, "@frida", "punycode")],
        ["querystring", crosspath.join(shimDir, "@frida", "querystring")],
        ["readable-stream", crosspath.join(shimDir, "@frida", "readable-stream")],
        ["stream", crosspath.join(shimDir, "@frida", "stream")],
        ["string_decoder", crosspath.join(shimDir, "@frida", "string_decoder")],
        ["timers", crosspath.join(shimDir, "@frida", "timers")],
        ["tty", crosspath.join(shimDir, "@frida", "tty")],
        ["url", crosspath.join(shimDir, "@frida", "url")],
        ["util", crosspath.join(shimDir, "@frida", "util")],
        ["vm", crosspath.join(shimDir, "@frida", "vm")],
    ]);
    const nodeShimNames = [
        "assert",
        "buffer",
        "diagnostics_channel",
        "events",
        "fs",
        "http",
        "https",
        "net",
        "os",
        "path",
        "process",
        "punycode",
        "querystring",
        "stream",
        "string_decoder",
        "timers",
        "tty",
        "url",
        "util",
        "vm",
    ];
    for (const name of nodeShimNames) {
        const path = shims.get(name);
        shims.set("node:" + name, path);
    }
    return {
        projectNodeModulesDir,
        compilerNodeModulesDir,
        shimDir,
        shims,
    };
}
function makeCompilerOptions(projectRoot, system, options) {
    const defaultTsOptions = makeDefaultCompilerOptions();
    const softOptionNames = ["target", "lib", "strict"];
    const fixedTsOptions = Object.assign({}, defaultTsOptions);
    for (const name of softOptionNames) {
        delete fixedTsOptions[name];
    }
    let opts;
    const configFileHost = new FridaConfigFileHost(projectRoot, system);
    const userOpts = ts.getParsedCommandLineOfConfigFile(crosspath.join(projectRoot, "tsconfig.json"), fixedTsOptions, configFileHost)?.options;
    if (userOpts !== undefined) {
        for (const name of softOptionNames) {
            const val = userOpts[name];
            if (val === undefined) {
                userOpts[name] = defaultTsOptions[name];
            }
        }
        delete userOpts.noEmit;
        opts = userOpts;
    }
    else {
        opts = defaultTsOptions;
    }
    opts.rootDir = projectRoot;
    opts.outDir = "/";
    if (options.sourceMaps === "included") {
        opts.sourceRoot = projectRoot;
        opts.sourceMap = true;
        opts.inlineSourceMap = false;
    }
    return opts;
}
export function makeDefaultCompilerOptions() {
    return {
        target: ts.ScriptTarget.ES2020,
        lib: ["lib.es2020.d.ts"],
        module: ts.ModuleKind.ES2020,
        moduleResolution: ts.ModuleResolutionKind.Node16,
        allowSyntheticDefaultImports: true,
        resolveJsonModule: true,
        allowJs: true,
        strict: true
    };
}
function createBundler(entrypoint, projectRoot, assets, system, options) {
    const { sourceMaps, compression, } = options;
    const events = new EventEmitter();
    const output = new Map();
    const pendingModules = [];
    const processedModules = new Set();
    const jsonFilePaths = new Set();
    const modules = new Map();
    const externalSources = new Map();
    system.writeFile = (path, data, writeByteOrderMark) => {
        output.set(path, data);
    };
    function markAllProgramSourcesAsProcessed(program) {
        for (const sf of program.getSourceFiles()) {
            if (!sf.isDeclarationFile) {
                const outPath = changeFileExtension(sf.fileName, "js");
                processedModules.add(outPath);
            }
        }
    }
    function getExternalSourceFile(path) {
        let file = externalSources.get(path);
        if (file !== undefined) {
            return file;
        }
        const sourceText = system.readFile(path, "utf-8");
        if (sourceText === undefined) {
            throw new Error(`unable to open ${path}`);
        }
        file = ts.createSourceFile(path, sourceText, ts.ScriptTarget.ES2020, true, ts.ScriptKind.JS);
        externalSources.set(path, file);
        events.emit("externalSourceFileAdded", file);
        return file;
    }
    function assetNameFromFilePath(path) {
        if (path.startsWith(compilerRoot)) {
            return path.substring(compilerRoot.length);
        }
        if (path.startsWith(projectRoot)) {
            return path.substring(projectRoot.length);
        }
        throw new Error(`unexpected file path: ${path}`);
    }
    return {
        events,
        bundle(program) {
            markAllProgramSourcesAsProcessed(program);
            for (const sf of program.getSourceFiles()) {
                if (!sf.isDeclarationFile) {
                    const { fileName } = sf;
                    const path = changeFileExtension(fileName, "js");
                    const mod = {
                        type: "esm",
                        path,
                        file: sf,
                        aliases: new Set(),
                    };
                    modules.set(assetNameFromFilePath(path), mod);
                    processJSModule(mod, processedModules, pendingModules, jsonFilePaths);
                }
            }
            const missing = new Set();
            let ref;
            while ((ref = pendingModules.shift()) !== undefined) {
                const refName = ref.name;
                processedModules.add(ref.name);
                let resolveRes;
                try {
                    resolveRes = resolveModuleReference(ref, assets, system);
                }
                catch (e) {
                    missing.add(refName);
                    continue;
                }
                const [modPath, needsAlias] = resolveRes;
                const assetName = assetNameFromFilePath(modPath);
                let mod = modules.get(assetName);
                if (mod === undefined) {
                    const sourceFile = getExternalSourceFile(modPath);
                    mod = {
                        type: detectModuleType(modPath, system),
                        path: modPath,
                        file: sourceFile,
                        aliases: new Set(),
                    };
                    output.set(assetName, sourceFile.text);
                    modules.set(assetName, mod);
                    processedModules.add(modPath);
                    processJSModule(mod, processedModules, pendingModules, jsonFilePaths);
                }
                if (needsAlias) {
                    let alias;
                    if (crosspath.isAbsolute(refName)) {
                        alias = refName.substring(projectRoot.length);
                    }
                    else {
                        alias = refName;
                    }
                    mod.aliases.add(alias);
                }
            }
            if (missing.size > 0) {
                throw new Error(`unable to resolve:\n\t${Array.from(missing).sort().join("\n\t")}`);
            }
            const legacyModules = Array.from(modules.values()).filter(m => m.type === "cjs").map(m => m.path).sort();
            if (legacyModules.length > 0) {
                throw new Error(`only able to bundle ECMAScript modules, detected CommonJS:\n\t${legacyModules.join("\n\t")}`);
            }
            for (const path of jsonFilePaths) {
                const assetName = assetNameFromFilePath(path);
                if (!output.has(assetName)) {
                    output.set(assetName, system.readFile(path));
                }
            }
            for (const [name, data] of output) {
                if (name.endsWith(".js")) {
                    let code = data;
                    const lines = code.split("\n");
                    const n = lines.length;
                    const lastLine = lines[n - 1];
                    const sourceMapToken = "//# sourceMappingURL=";
                    if (lastLine.startsWith(sourceMapToken)) {
                        const precedingLines = lines.slice(0, n - 1);
                        code = precedingLines.join("\n");
                        if (sourceMaps === "included") {
                            const inlinedSourceMapOrPath = lastLine.substring(sourceMapToken.length);
                            const dataUrlToken = "data:application/json;base64,";
                            const isInlined = inlinedSourceMapOrPath.startsWith(dataUrlToken);
                            const sourceMapPath = isInlined
                                ? `${name}.map`
                                : crosspath.join(crosspath.dirname(name), inlinedSourceMapOrPath);
                            if (!output.has(sourceMapPath)) {
                                const content = isInlined
                                    ? system.base64decode?.(inlinedSourceMapOrPath.substring(dataUrlToken.length))
                                    : system.readFile(`.${sourceMapPath}`);
                                if (content !== undefined) {
                                    output.set(sourceMapPath, content);
                                }
                            }
                        }
                    }
                    if (compression === "terser") {
                        const mod = modules.get(name);
                        const originPath = mod.path;
                        const originFilename = crosspath.basename(originPath);
                        const minifySources = {};
                        minifySources[originFilename] = code;
                        const minifyOpts = {
                            ecma: 2020,
                            compress: {
                                module: true,
                                global_defs: {
                                    "process.env.FRIDA_COMPILE": true
                                },
                            },
                            mangle: {
                                module: true,
                            },
                        };
                        const mapName = name + ".map";
                        if (sourceMaps === "included") {
                            const mapOpts = {
                                asObject: true,
                                root: crosspath.dirname(originPath) + "/",
                                filename: name.substring(name.lastIndexOf("/") + 1),
                            };
                            const inputMap = output.get(mapName);
                            if (inputMap !== undefined) {
                                mapOpts.content = inputMap;
                            }
                            minifyOpts.sourceMap = mapOpts;
                        }
                        const result = minify(minifySources, minifyOpts);
                        code = result.code;
                        if (sourceMaps === "included") {
                            const map = result.map;
                            const prefixLength = map.sourceRoot.length;
                            map.sources = map.sources.map((s) => s.substring(prefixLength));
                            output.set(mapName, JSON.stringify(map));
                        }
                    }
                    output.set(name, code);
                }
                else if (name.endsWith(".json")) {
                    output.set(name, jsonToModule(data));
                }
            }
            const names = [];
            const orderedNames = Array.from(output.keys());
            orderedNames.sort();
            const maps = new Set(orderedNames.filter(name => name.endsWith(".map")));
            const entrypointNormalized = crosspath.normalize(entrypoint.output);
            for (const name of orderedNames.filter(name => !name.endsWith(".map"))) {
                let index = (crosspath.normalize(name) === entrypointNormalized) ? 0 : names.length;
                const mapName = name + ".map";
                if (maps.has(mapName)) {
                    names.splice(index, 0, mapName);
                    index++;
                }
                names.splice(index, 0, name);
            }
            const chunks = [];
            chunks.push("📦\n");
            for (const name of names) {
                const rawData = Buffer.from(output.get(name));
                chunks.push(`${rawData.length} ${name}\n`);
                const mod = modules.get(name);
                if (mod !== undefined) {
                    for (const alias of mod.aliases) {
                        chunks.push(`↻ ${alias}\n`);
                    }
                }
            }
            chunks.push("✄\n");
            let i = 0;
            for (const name of names) {
                if (i !== 0) {
                    chunks.push("\n✄\n");
                }
                const data = output.get(name);
                chunks.push(data);
                i++;
            }
            return chunks.join("");
        },
        invalidate(path) {
            output.delete(assetNameFromFilePath(path));
            processedModules.clear();
            externalSources.delete(path);
        }
    };
}
function detectModuleType(modPath, sys) {
    let curDir = crosspath.dirname(modPath);
    while (true) {
        const rawPkgMeta = sys.readFile(crosspath.join(curDir, "package.json"));
        if (rawPkgMeta !== undefined) {
            const pkgMeta = JSON.parse(rawPkgMeta);
            if (pkgMeta.type === "module" || pkgMeta.module !== undefined) {
                return "esm";
            }
            break;
        }
        const nextDir = crosspath.dirname(curDir);
        if (nextDir === curDir) {
            break;
        }
        curDir = nextDir;
    }
    return "cjs";
}
function resolveModuleReference(ref, assets, system) {
    const refName = ref.name;
    const requesterPath = ref.referrer.path;
    let modPath;
    let needsAlias = false;
    if (crosspath.isAbsolute(refName)) {
        modPath = refName;
    }
    else {
        const tokens = refName.split("/");
        let pkgName;
        let subPath;
        if (tokens[0].startsWith("@")) {
            pkgName = tokens[0] + "/" + tokens[1];
            subPath = tokens.slice(2);
        }
        else {
            pkgName = tokens[0];
            subPath = tokens.slice(1);
        }
        const shimPath = assets.shims.get(pkgName);
        if (shimPath !== undefined) {
            if (shimPath.endsWith(".js")) {
                modPath = shimPath;
            }
            else {
                modPath = crosspath.join(shimPath, ...subPath);
            }
            needsAlias = true;
        }
        else {
            const linkedCompilerRoot = crosspath.join(assets.projectNodeModulesDir, "frida-compile");
            const { shimDir } = assets;
            if (requesterPath.startsWith(compilerRoot) ||
                requesterPath.startsWith(linkedCompilerRoot) ||
                requesterPath.startsWith(shimDir)) {
                modPath = crosspath.join(shimDir, ...tokens);
            }
            else {
                modPath = crosspath.join(assets.projectNodeModulesDir, ...tokens);
            }
            needsAlias = subPath.length > 0;
        }
    }
    if (system.directoryExists(modPath)) {
        const rawPkgMeta = system.readFile(crosspath.join(modPath, "package.json"));
        if (rawPkgMeta !== undefined) {
            const pkgMeta = JSON.parse(rawPkgMeta);
            const pkgMain = pkgMeta.module ?? pkgMeta.main ?? "index.js";
            let pkgEntrypoint = crosspath.join(modPath, pkgMain);
            if (system.directoryExists(pkgEntrypoint)) {
                pkgEntrypoint = crosspath.join(pkgEntrypoint, "index.js");
            }
            modPath = pkgEntrypoint;
            needsAlias = true;
        }
        else {
            modPath = crosspath.join(modPath, "index.js");
        }
    }
    if (!system.fileExists(modPath)) {
        modPath += ".js";
        if (!system.fileExists(modPath)) {
            throw new Error("unable to resolve module");
        }
    }
    return [modPath, needsAlias];
}
function processJSModule(mod, processedModules, pendingModules, jsonFilePaths) {
    const moduleDir = crosspath.dirname(mod.path);
    const isCJS = mod.type === "cjs";
    ts.forEachChild(mod.file, visit);
    function visit(node) {
        if (ts.isImportDeclaration(node)) {
            visitImportDeclaration(node);
        }
        else if (ts.isExportDeclaration(node)) {
            visitExportDeclaration(node);
        }
        else if (isCJS && ts.isCallExpression(node)) {
            visitCallExpression(node);
            ts.forEachChild(node, visit);
        }
        else {
            ts.forEachChild(node, visit);
        }
    }
    function visitImportDeclaration(imp) {
        const depName = imp.moduleSpecifier.text;
        maybeAddModuleToPending(depName);
    }
    function visitExportDeclaration(exp) {
        const specifier = exp.moduleSpecifier;
        if (specifier === undefined) {
            return;
        }
        const depName = specifier.text;
        maybeAddModuleToPending(depName);
    }
    function visitCallExpression(call) {
        const expr = call.expression;
        if (!ts.isIdentifier(expr)) {
            return;
        }
        if (expr.escapedText !== "require") {
            return;
        }
        const args = call.arguments;
        if (args.length !== 1) {
            return;
        }
        const arg = args[0];
        if (!ts.isStringLiteral(arg)) {
            return;
        }
        const depName = arg.text;
        maybeAddModuleToPending(depName);
    }
    function maybeAddModuleToPending(name) {
        const ref = name.startsWith(".") ? crosspath.join(moduleDir, name) : name;
        if (name.endsWith(".json")) {
            jsonFilePaths.add(ref);
        }
        else if (!processedModules.has(ref)) {
            pendingModules.push({ name: ref, referrer: mod });
        }
    }
}
function useStrictRemovalTransformer() {
    return context => {
        return sourceFile => {
            const visitor = (node) => {
                if (ts.isExpressionStatement(node)) {
                    const { expression } = node;
                    if (ts.isStringLiteral(expression) && expression.text === "use strict") {
                        return [];
                    }
                }
                return ts.visitEachChild(node, visitor, context);
            };
            return ts.visitNode(sourceFile, visitor);
        };
    };
}
function jsonToModule(json) {
    const result = [];
    const data = JSON.parse(json);
    if (typeof data === "object" && data !== null) {
        const obj = data;
        let identifier = "d";
        let candidate = identifier;
        let serial = 1;
        while (obj.hasOwnProperty(candidate)) {
            candidate = identifier + serial;
            serial++;
        }
        identifier = candidate;
        result.push(`const ${identifier} = ${json.trim()};`);
        result.push(`export default ${identifier};`);
        for (const member of Object.keys(data).filter(identifier => !checkIdentifier(identifier, "es2015", true))) {
            result.push(`export const ${member} = ${identifier}.${member};`);
        }
    }
    else {
        result.push(`export default ${json.trim()};`);
    }
    return result.join("\n");
}
class FridaConfigFileHost {
    constructor(projectRoot, sys) {
        this.projectRoot = projectRoot;
        this.sys = sys;
        this.useCaseSensitiveFileNames = true;
    }
    readDirectory(rootDir, extensions, excludes, includes, depth) {
        return this.sys.readDirectory(rootDir, extensions, excludes, includes, depth);
    }
    fileExists(path) {
        return this.sys.fileExists(path);
    }
    readFile(path) {
        return this.sys.readFile(path);
    }
    trace(s) {
        console.log(s);
    }
    getCurrentDirectory() {
        return this.projectRoot;
    }
    onUnRecoverableConfigFileDiagnostic(diagnostic) {
    }
}
function detectCompilerRoot() {
    if (process.env.FRIDA_COMPILE !== undefined) {
        return "/frida-compile";
    }
    else {
        return crosspath.dirname(crosspath.dirname(crosspath.urlToFilename(import.meta.url)));
    }
}
function changeFileExtension(path, ext) {
    const pathWithoutExtension = path.substring(0, path.lastIndexOf("."));
    return pathWithoutExtension + "." + ext;
}
