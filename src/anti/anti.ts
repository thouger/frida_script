// @ts-nocheck
// Anti-debug + anti-Frida helpers (merged from FridaContainer Anti.anti_debug() and src/anti/anti_frida.js).
//
// Keep this module side-effect free: hooks are only installed when calling exported functions.

type ReplacePair = readonly [from: string, to: string];

export interface AntiDebugOptions {
  log?: boolean;
  hookFgets?: boolean;
  hookExit?: boolean;
  hookFork?: boolean;
  hookKill?: boolean;
  hookPtrace?: boolean;
  hookCxaThrow?: boolean;
}

export interface AntiFridaOptions {
  log?: boolean;
  // Core hooks used by most anti-Frida checks.
  hookOpenProc?: boolean;
  hookFgets?: boolean;
  hookReadlink?: boolean;
  hookReadlinkat?: boolean;
  hookStrstr?: boolean;

  // Optional/noisy hooks (kept from the original anti_frida.js).
  hookPopen?: boolean;
  hookSymlink?: boolean;
  hookSymlinkat?: boolean;
  hookInet?: boolean;
  hookSocket?: boolean;
  hookConnect?: boolean;
  hookSend?: boolean;
  hookSendto?: boolean;
  hookPthreadCreate?: boolean;

  // Tuning.
  processName?: string; // default: /proc/self/cmdline
  monitorLibrary?: string; // used by pthread_create hook
  aggressiveReplace?: boolean; // also replace very generic strings like "server", "re."
  replaceToken?: string; // default: "Faking"
}

export interface AntiAllOptions {
  debug?: AntiDebugOptions;
  frida?: AntiFridaOptions;
}

export interface NeteaseNisBypassOptions {
  log?: boolean;
  returnValue?: boolean; // default: true
  retryMs?: number; // default: 50
}

let installedFgets = false;
let installedExit = false;
let installedFork = false;
let installedKill = false;
let installedPtrace = false;
let installedCxaThrow = false;

let installedOpenProc = false;
let installedReadlink = false;
let installedReadlinkat = false;
let installedStrstr = false;

let installedPopen = false;
let installedSymlink = false;
let installedSymlinkat = false;
let installedInet = false;
let installedSocket = false;
let installedConnect = false;
let installedSend = false;
let installedSendto = false;
let installedPthreadCreate = false;
let installedProcReadSanitizer = false;

function logEnabled(enabled: boolean | undefined, tag: string, ...args: unknown[]): void {
  if (enabled) console.log(`[${tag}]`, ...args);
}

function applyReplacements(input: string, pairs: readonly ReplacePair[]): string {
  let out = input;
  for (const [from, to] of pairs) {
    if (from.length === 0) continue;
    // String#replaceAll is not available on all Frida JS runtimes.
    out = out.split(from).join(to);
  }
  return out;
}

function getLR(context: CpuContext): NativePointer {
  // arm/arm64: lr is present in CpuContext
  const anyCtx = context as unknown as { lr?: NativePointer };
  return anyCtx.lr ?? ptr(0);
}

function moduleByAddr(addr: NativePointer): string {
  try {
    return Process.getModuleByAddress(addr).name;
  } catch {
    return "<unknown>";
  }
}

function formatBacktrace(context: CpuContext): string {
  try {
    return Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");
  } catch {
    return "<no-backtrace>";
  }
}

function writeUtf8Trunc(dst: NativePointer, s: string, maxBytes: number): void {
  // fgets buffer is size bytes; ensure we never write past it.
  // (Frida writes a terminating NUL; so we cap at maxBytes-1).
  const cap = Math.max(0, maxBytes - 1);
  const truncated = s.length <= cap ? s : s.slice(0, cap);
  dst.writeUtf8String(truncated);
}

function getProcessNameFromCmdline(): string | null {
  const openPtr = Module.findExportByName("libc.so", "open");
  const readPtr = Module.findExportByName("libc.so", "read");
  const closePtr = Module.findExportByName("libc.so", "close");
  if (openPtr === null || readPtr === null || closePtr === null) return null;

  // bionic open() is varargs; most callers pass only 2 args.
  const open = new NativeFunction(openPtr, "int", ["pointer", "int"]);
  const read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);
  const close = new NativeFunction(closePtr, "int", ["int"]);

  const path = Memory.allocUtf8String("/proc/self/cmdline");
  const fd = (open as any)(path, 0) as number;
  if (fd === -1) return null;

  const buf = Memory.alloc(0x1000);
  (read as any)(fd, buf, 0x1000);
  (close as any)(fd);

  try {
    const name = Memory.readUtf8String(buf);
    return name && name.length > 0 ? name : null;
  } catch {
    return null;
  }
}

function fridaReplacePairs(token: string, aggressive: boolean): ReplacePair[] {
  // Safer default set (enough for most string-based checks).
  const base: ReplacePair[] = [
    ["re.frida.server", token],
    ["frida-agent-64.so", token],
    ["frida-agent-32.so", token],
    ["frida-helper-64.so", token],
    ["frida-helper-32.so", token],
    ["frida-helper", token],
    ["frida-agent", token],
    ["pool-frida", token],
    ["pool-spawner", token],
    ["gum-js-loop", token],
    ["frida_agent_main", token],
    ["linjector", token],
    ["gmain", token],
    ["magisk", token],
    ["/sbin/.magisk", token],
    [".magisk", token],
    ["libriru", token],
    ["xposed", token],
    ["/data/local/tmp", "/data"],
    ["frida", token],
  ];

  if (!aggressive) return base;

  // Aggressive mode: mirrors some very broad replacements in the original anti_frida.js.
  // This can break legitimate strings; only enable if needed for a specific target.
  return base.concat([
    ["re.", token],
    ["frida.", token],
    ["frida-", token],
    ["server", token],
    ["frida-server", token],
  ]);
}

function asciiBytes(s: string): Uint8Array {
  // /proc files are ASCII; keep it simple and predictable.
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function replaceAsciiInPlace(buf: Uint8Array, needle: Uint8Array, repl: Uint8Array): void {
  const n = buf.length;
  const m = needle.length;
  if (m === 0 || m !== repl.length || n < m) return;

  // Naive scan; good enough for small /proc chunks.
  for (let i = 0; i <= n - m; i++) {
    let hit = true;
    for (let j = 0; j < m; j++) {
      if (buf[i + j] !== needle[j]) {
        hit = false;
        break;
      }
    }
    if (!hit) continue;
    for (let j = 0; j < m; j++) buf[i + j] = repl[j];
    i += m - 1;
  }
}

function scrubTracerPidInPlace(buf: Uint8Array): void {
  // Find "TracerPid:" then zero out digits until newline.
  const needle = asciiBytes("TracerPid:");
  const n = buf.length;
  const m = needle.length;
  for (let i = 0; i <= n - m; i++) {
    let hit = true;
    for (let j = 0; j < m; j++) {
      if (buf[i + j] !== needle[j]) {
        hit = false;
        break;
      }
    }
    if (!hit) continue;
    // Scan forward for digits after ':' (typically "TracerPid:\t1234\n")
    for (let k = i + m; k < n; k++) {
      const c = buf[k];
      if (c === 0x0a) break; // '\n'
      if (c >= 0x30 && c <= 0x39) buf[k] = 0x30; // '0'
    }
    i += m - 1;
  }
}

function sanitizeProcReadBuffer(bufPtr: NativePointer, n: number): void {
  if (n <= 0) return;
  // Cap to avoid huge allocations on unexpected reads.
  const cap = Math.min(n, 4096);
  const ab = bufPtr.readByteArray(cap);
  if (ab === null) return;
  const u8 = new Uint8Array(ab);

  // Keep replacements same-length to avoid changing byte counts.
  replaceAsciiInPlace(u8, asciiBytes("frida"), asciiBytes("xxxxx"));
  replaceAsciiInPlace(u8, asciiBytes("gum-js-loop"), asciiBytes("gum-js-xxxx"));
  replaceAsciiInPlace(u8, asciiBytes("/data/local/tmp"), asciiBytes("/data/local/xxx"));
  replaceAsciiInPlace(u8, asciiBytes("linjector"), asciiBytes("lxxxxxxor"));
  replaceAsciiInPlace(u8, asciiBytes("gmain"), asciiBytes("xxxxx"));
  replaceAsciiInPlace(u8, asciiBytes("pool-frida"), asciiBytes("pool-xxxxx"));
  // root-ish strings sometimes bundled with anti-Frida checks
  replaceAsciiInPlace(u8, asciiBytes("magisk"), asciiBytes("xxxxx"));
  replaceAsciiInPlace(u8, asciiBytes("libriru"), asciiBytes("xxxxxx"));
  replaceAsciiInPlace(u8, asciiBytes("xposed"), asciiBytes("xxxxx"));

  scrubTracerPidInPlace(u8);

  bufPtr.writeByteArray(u8.buffer);
}

function installFgetsHook(log: boolean, token: string, aggressive: boolean): void {
  if (installedFgets) return;
  installedFgets = true;

  const tag = "anti_fgets";
  const fgetsPtr = Module.findExportByName(null, "fgets");
  logEnabled(log, tag, "addr:", fgetsPtr);
  if (fgetsPtr === null) return;
  const pairs = fridaReplacePairs(token, aggressive);

  // Use attach (not replace) so fgets keeps running normally; we only post-process its output buffer.
  Interceptor.attach(fgetsPtr, {
    onEnter(args) {
      this._buf = args[0];
      this._size = args[1].toInt32();
      this._ctx = this.context;
    },
    onLeave(_retval) {
      const buffer = this._buf as NativePointer;
      const size = this._size as number;
      const ctx = (this._ctx ?? null) as CpuContext | null;
      const lr = ctx ? getLR(ctx) : ptr(0);

      let s: string | null = null;
      try {
        s = Memory.readUtf8String(buffer);
      } catch {
        s = null;
      }
      if (s === null) return;

      let out: string | null = null;
      let reason: string | null = null;

      if (s.indexOf("TracerPid:") !== -1) {
        out = "TracerPid:\t0";
        reason = "TracerPid";
      } else if (s.indexOf("State:\tt (tracing stop)") !== -1) {
        out = "State:\tS (sleeping)";
        reason = "State";
      } else if (s.indexOf("ptrace_stop") !== -1) {
        out = "sys_epoll_wait";
        reason = "ptrace_stop";
      } else if (s.indexOf(") t") !== -1) {
        out = s.split(") t").join(") S");
        reason = "stat_t";
      } else if (s.indexOf("SigBlk:") !== -1) {
        out = "SigBlk:\t0000000000001204";
        reason = "SigBlk";
      }

      // Also redact common Frida strings when they appear in /proc/* reads via fgets.
      const redacted = applyReplacements(out ?? s, pairs);
      if (redacted !== (out ?? s)) {
        out = redacted;
        reason = reason ?? "frida_str";
      }

      if (out !== null) {
        writeUtf8Trunc(buffer, out, size);
        if (log) {
          const mod = lr.isNull() ? "<no-lr>" : moduleByAddr(lr);
          logEnabled(log, tag, `${reason}:`, `"${s}" -> "${out}"`, "lr:", lr, `(${mod})`);
          if (ctx) logEnabled(log, tag, "backtrace:\n" + formatBacktrace(ctx));
        }
      }
    },
  });
}

export function antiDebug(options: AntiDebugOptions = {}): void {
  const opt: Required<AntiDebugOptions> = {
    log: options.log ?? true,
    hookFgets: options.hookFgets ?? true,
    hookExit: options.hookExit ?? true,
    hookFork: options.hookFork ?? true,
    hookKill: options.hookKill ?? true,
    hookPtrace: options.hookPtrace ?? true,
    hookCxaThrow: options.hookCxaThrow ?? true,
  };

  if (opt.hookFgets) installFgetsHook(opt.log, "dmemory", false);

  if (opt.hookExit && !installedExit) {
    installedExit = true;
    const tag = "anti_exit";
    const exitPtr = Module.findExportByName(null, "_exit") ?? Module.findExportByName(null, "exit");
    logEnabled(opt.log, tag, "addr:", exitPtr);
    if (exitPtr !== null) {
      Interceptor.replace(
        exitPtr,
        new NativeCallback(function (this: any, code: number): void {
          const ctx = (this?.context ?? null) as CpuContext | null;
          const lr = ctx ? getLR(ctx) : ptr(0);
          logEnabled(opt.log, tag, "called:", code, "lr:", lr);
          if (ctx) logEnabled(opt.log, tag, "backtrace:\n" + formatBacktrace(ctx));
          // swallow
        }, "void", ["int"])
      );
    }
  }

  if (opt.hookFork && !installedFork) {
    installedFork = true;
    const tag = "anti_fork";
    const forkPtr = Module.findExportByName(null, "fork");
    logEnabled(opt.log, tag, "addr:", forkPtr);
    if (forkPtr !== null) {
      Interceptor.replace(
        forkPtr,
        new NativeCallback(function (): number {
          logEnabled(opt.log, tag, "called (forcing failure)");
          return -1;
        }, "int", [])
      );
    }
  }

  if (opt.hookKill && !installedKill) {
    installedKill = true;
    const tag = "anti_kill";
    const killPtr = Module.findExportByName(null, "kill");
    logEnabled(opt.log, tag, "addr:", killPtr);
    if (killPtr !== null) {
      Interceptor.replace(
        killPtr,
        new NativeCallback(function (this: any, pid: number, sig: number): number {
          const ctx = (this?.context ?? null) as CpuContext | null;
          const lr = ctx ? getLR(ctx) : ptr(0);
          logEnabled(opt.log, tag, "called:", pid, sig, "lr:", lr);
          if (ctx) logEnabled(opt.log, tag, "backtrace:\n" + formatBacktrace(ctx));
          return 0;
        }, "int", ["int", "int"])
      );
    }
  }

  if (opt.hookPtrace && !installedPtrace) {
    installedPtrace = true;
    const tag = "anti_ptrace";
    const ptracePtr = Module.findExportByName(null, "ptrace");
    logEnabled(opt.log, tag, "addr:", ptracePtr);
    if (ptracePtr !== null) {
      Interceptor.replace(
        ptracePtr,
        new NativeCallback(function (_req: number, _pid: number, _addr: NativePointer, _data: NativePointer): number {
          logEnabled(opt.log, tag, "called (returning success)");
          return 0;
        }, "long", ["int", "int", "pointer", "pointer"])
      );
    }
  }

  // Many apps terminate themselves after detecting Frida by raising SIGTRAP/SIGABRT.
  // These hooks are intentionally simple: swallow the signal dispatch.
  if (opt.log) {
    // no-op; keep parity with other hooks
  }
  const raisePtr = Module.findExportByName(null, "raise");
  if (raisePtr !== null) {
    Interceptor.replace(
      raisePtr,
      new NativeCallback(function (sig: number): number {
        // swallow
        return 0;
      }, "int", ["int"])
    );
  }
  const abortPtr = Module.findExportByName(null, "abort");
  if (abortPtr !== null) {
    Interceptor.replace(
      abortPtr,
      new NativeCallback(function (): void {
        // swallow
      }, "void", [])
    );
  }
  const tgkillPtr = Module.findExportByName(null, "tgkill");
  if (tgkillPtr !== null) {
    Interceptor.replace(
      tgkillPtr,
      new NativeCallback(function (_tgid: number, _tid: number, _sig: number): number {
        return 0;
      }, "int", ["int", "int", "int"])
    );
  }
  const tkillPtr = Module.findExportByName(null, "tkill");
  if (tkillPtr !== null) {
    Interceptor.replace(
      tkillPtr,
      new NativeCallback(function (_tid: number, _sig: number): number {
        return 0;
      }, "int", ["int", "int"])
    );
  }
  const pthreadKillPtr = Module.findExportByName(null, "pthread_kill");
  if (pthreadKillPtr !== null) {
    Interceptor.replace(
      pthreadKillPtr,
      new NativeCallback(function (_thread: NativePointer, _sig: number): number {
        return 0;
      }, "int", ["pointer", "int"])
    );
  }

  if (opt.hookCxaThrow && !installedCxaThrow) {
    installedCxaThrow = true;
    const tag = "anti___cxa_throw";
    const cxaThrowPtr = Module.findExportByName(null, "__cxa_throw");
    logEnabled(opt.log, tag, "addr:", cxaThrowPtr);
    if (cxaThrowPtr !== null) {
      Interceptor.replace(
        cxaThrowPtr,
        new NativeCallback(function (this: any, exc: NativePointer, tinfo: NativePointer, dest: NativePointer): void {
          const ctx = (this?.context ?? null) as CpuContext | null;
          const lr = ctx ? getLR(ctx) : ptr(0);
          logEnabled(opt.log, tag, "called (swallowing)", "exc:", exc, "tinfo:", tinfo, "dest:", dest, "lr:", lr);
          if (ctx) logEnabled(opt.log, tag, "backtrace:\n" + formatBacktrace(ctx));
          // swallow
        }, "void", ["pointer", "pointer", "pointer"])
      );
    }
  }
}

export function antiFrida(options: AntiFridaOptions = {}): void {
  const opt: Required<AntiFridaOptions> = {
    log: options.log ?? true,

    hookOpenProc: options.hookOpenProc ?? true,
    hookFgets: options.hookFgets ?? true,
    hookReadlink: options.hookReadlink ?? true,
    hookReadlinkat: options.hookReadlinkat ?? true,
    hookStrstr: options.hookStrstr ?? true,

    hookPopen: options.hookPopen ?? false,
    hookSymlink: options.hookSymlink ?? false,
    hookSymlinkat: options.hookSymlinkat ?? false,
    hookInet: options.hookInet ?? false,
    hookSocket: options.hookSocket ?? false,
    hookConnect: options.hookConnect ?? false,
    hookSend: options.hookSend ?? false,
    hookSendto: options.hookSendto ?? false,
    hookPthreadCreate: options.hookPthreadCreate ?? false,

    processName: options.processName ?? (getProcessNameFromCmdline() ?? "unknown"),
    monitorLibrary: options.monitorLibrary ?? "libxyz.so",
    aggressiveReplace: options.aggressiveReplace ?? false,
    replaceToken: options.replaceToken ?? "Faking",
  };

  if (opt.hookFgets) installFgetsHook(opt.log, opt.replaceToken + "Gets", opt.aggressiveReplace);

  if (opt.hookOpenProc && !installedOpenProc) {
    installedOpenProc = true;
    const tag = "anti_open";

    // Some apps validate that the returned fd still points to /proc/... (e.g. via /proc/self/fd/<fd>).
    // So we DO NOT redirect fd to a fake file here. Instead, track proc fds and sanitize reads in-place.
    if (!installedProcReadSanitizer) {
      installedProcReadSanitizer = true;

      const openPtr = Module.findExportByName("libc.so", "open");
      const openatPtr = Module.findExportByName("libc.so", "openat");
      const closePtr = Module.findExportByName("libc.so", "close");
      const readPtr = Module.findExportByName("libc.so", "read");
      const pread64Ptr = Module.findExportByName("libc.so", "pread64");

      if (openPtr === null || closePtr === null || readPtr === null) {
        logEnabled(opt.log, tag, "missing libc exports (open/close/read)");
        return;
      }

      const tracked = new Map<number, string>(); // fd -> path

      function shouldTrack(path: string): boolean {
        if (path.indexOf("/proc/") === -1) return false;
        // Keep it narrow to avoid touching unrelated /proc reads.
        return (
          path.indexOf("/maps") !== -1 ||
          path.indexOf("/task/") !== -1 ||
          path.indexOf("/status") !== -1 ||
          path.indexOf("/mounts") !== -1 ||
          path.indexOf("/exe") !== -1
        );
      }

      Interceptor.attach(openPtr, {
        onEnter(args) {
          try {
            const path = args[0].readCString();
            if (shouldTrack(path)) this._path = path;
          } catch {
            // ignore
          }
        },
        onLeave(retval) {
          const fd = retval.toInt32();
          const path = this._path as string | undefined;
          if (fd >= 0 && path) {
            tracked.set(fd, path);
            logEnabled(opt.log, tag, "track fd:", fd, "path:", path);
          }
        },
      });

      if (openatPtr !== null) {
        Interceptor.attach(openatPtr, {
          onEnter(args) {
            try {
              const path = args[1].readCString();
              if (shouldTrack(path)) this._path = path;
            } catch {
              // ignore
            }
          },
          onLeave(retval) {
            const fd = retval.toInt32();
            const path = this._path as string | undefined;
            if (fd >= 0 && path) {
              tracked.set(fd, path);
              logEnabled(opt.log, tag, "track fd(openat):", fd, "path:", path);
            }
          },
        });
      }

      Interceptor.attach(closePtr, {
        onEnter(args) {
          const fd = args[0].toInt32();
          if (tracked.has(fd)) tracked.delete(fd);
        },
      });

      Interceptor.attach(readPtr, {
        onEnter(args) {
          const fd = args[0].toInt32();
          if (!tracked.has(fd)) {
            this._skip = true;
            return;
          }
          this._skip = false;
          this._fd = fd;
          this._buf = args[1];
        },
        onLeave(retval) {
          if (this._skip) return;
          const n = retval.toInt32();
          if (n <= 0) return;
          try {
            sanitizeProcReadBuffer(this._buf as NativePointer, n);
          } catch {
            // ignore
          }
        },
      });

      if (pread64Ptr !== null) {
        Interceptor.attach(pread64Ptr, {
          onEnter(args) {
            const fd = args[0].toInt32();
            if (!tracked.has(fd)) {
              this._skip = true;
              return;
            }
            this._skip = false;
            this._buf = args[1];
          },
          onLeave(retval) {
            if (this._skip) return;
            const n = retval.toInt32();
            if (n <= 0) return;
            try {
              sanitizeProcReadBuffer(this._buf as NativePointer, n);
            } catch {
              // ignore
            }
          },
        });
      }
    }
  }

  if (opt.hookReadlink && !installedReadlink) {
    installedReadlink = true;
    const tag = "anti_readlink";
    const readlinkPtr = Module.findExportByName("libc.so", "readlink");
    logEnabled(opt.log, tag, "addr:", readlinkPtr);
    if (readlinkPtr !== null) {
      const token = "/system/framework/services.jar";

      // Use attach: we only post-process the output buffer and return length.
      Interceptor.attach(readlinkPtr, {
        onEnter(args) {
          this._buf = args[1];
          this._bufsize = args[2].toInt32();
        },
        onLeave(retval) {
          const n = retval.toInt32();
          if (n <= 0) return;

          const buffer = this._buf as NativePointer;
          const bufsize = this._bufsize as number;

          let out = "";
          try {
            out = Memory.readUtf8String(buffer, n);
          } catch {
            return;
          }

          const suspicious =
            out.indexOf("frida") !== -1 ||
            out.indexOf("gum-js-loop") !== -1 ||
            out.indexOf("gmain") !== -1 ||
            out.indexOf("linjector") !== -1 ||
            out.indexOf("/data/local/tmp") !== -1 ||
            out.indexOf("pool-frida") !== -1 ||
            out.indexOf("frida_agent_main") !== -1 ||
            out.indexOf("re.frida.server") !== -1;

          if (!suspicious) return;

          logEnabled(opt.log, tag, "redact:", out);
          const max = Math.max(0, bufsize - 1);
          const rep = token.length <= max ? token : token.slice(0, max);
          buffer.writeUtf8String(rep);
          retval.replace(rep.length);
        },
      });
    }
  }

  if (opt.hookReadlinkat && !installedReadlinkat) {
    installedReadlinkat = true;
    const tag = "anti_readlinkat";
    const readlinkatPtr = Module.findExportByName("libc.so", "readlinkat");
    logEnabled(opt.log, tag, "addr:", readlinkatPtr);
    if (readlinkatPtr !== null) {
      const token = "/system/framework/services.jar";

      Interceptor.attach(readlinkatPtr, {
        onEnter(args) {
          this._buf = args[2];
          this._bufsize = args[3].toInt32();
        },
        onLeave(retval) {
          const n = retval.toInt32();
          if (n <= 0) return;

          const buffer = this._buf as NativePointer;
          const bufsize = this._bufsize as number;

          let out = "";
          try {
            out = Memory.readUtf8String(buffer, n);
          } catch {
            return;
          }

          const suspicious =
            out.indexOf("frida") !== -1 ||
            out.indexOf("gum-js-loop") !== -1 ||
            out.indexOf("gmain") !== -1 ||
            out.indexOf("linjector") !== -1 ||
            out.indexOf("/data/local/tmp") !== -1 ||
            out.indexOf("pool-frida") !== -1 ||
            out.indexOf("frida_agent_main") !== -1 ||
            out.indexOf("re.frida.server") !== -1;

          if (!suspicious) return;

          logEnabled(opt.log, tag, "redact:", out);
          const max = Math.max(0, bufsize - 1);
          const rep = token.length <= max ? token : token.slice(0, max);
          buffer.writeUtf8String(rep);
          retval.replace(rep.length);
        },
      });
    }
  }

  if (opt.hookStrstr && !installedStrstr) {
    installedStrstr = true;
    const tag = "anti_strstr";
    const strstrPtr = Module.findExportByName(null, "strstr");
    logEnabled(opt.log, tag, "addr:", strstrPtr);
    if (strstrPtr !== null) {
      Interceptor.attach(strstrPtr, {
        onEnter(args) {
          this._hit = false;
          let s1 = "";
          let s2 = "";
          try {
            s1 = args[0].readCString();
            s2 = args[1].readCString();
          } catch {
            return;
          }
          const combined = `${s1}\n${s2}`;
          if (
            combined.indexOf("frida") !== -1 ||
            combined.indexOf("gum-js-loop") !== -1 ||
            combined.indexOf("gmain") !== -1 ||
            combined.indexOf("linjector") !== -1 ||
            combined.indexOf("/data/local/tmp") !== -1 ||
            combined.indexOf("pool-frida") !== -1 ||
            combined.indexOf("frida_agent_main") !== -1 ||
            combined.indexOf("re.frida.server") !== -1 ||
            combined.indexOf("pool-spawner") !== -1 ||
            combined.indexOf("/sbin/.magisk") !== -1 ||
            combined.indexOf("magisk") !== -1 ||
            combined.indexOf("libriru") !== -1
          ) {
            this._hit = true;
            logEnabled(opt.log, tag, "strstr:", s1, s2);
          }
        },
        onLeave(retval) {
          if (this._hit) retval.replace(ptr(0));
        },
      });
    }
  }

  // Optional / noisy hooks below (kept for completeness; default off).

  if (opt.hookPopen && !installedPopen) {
    installedPopen = true;
    const tag = "popen";
    const popenPtr = Module.findExportByName("libc.so", "popen");
    if (popenPtr !== null) {
      const popen = new NativeFunction(popenPtr, "pointer", ["pointer", "pointer"]);
      Interceptor.replace(
        popenPtr,
        new NativeCallback(function (path: NativePointer, type: NativePointer): NativePointer {
          const rv = (popen as any)(path, type) as NativePointer;
          try {
            logEnabled(opt.log, tag, Memory.readUtf8String(path));
          } catch {
            // ignore
          }
          return rv;
        }, "pointer", ["pointer", "pointer"])
      );
    }
  }

  if (opt.hookSymlink && !installedSymlink) {
    installedSymlink = true;
    const tag = "symlink";
    const symlinkPtr = Module.findExportByName("libc.so", "symlink");
    if (symlinkPtr !== null) {
      const symlink = new NativeFunction(symlinkPtr, "int", ["pointer", "pointer"]);
      Interceptor.replace(
        symlinkPtr,
        new NativeCallback(function (target: NativePointer, path: NativePointer): number {
          const rv = (symlink as any)(target, path) as number;
          try {
            logEnabled(opt.log, tag, Memory.readUtf8String(target), Memory.readUtf8String(path));
          } catch {
            // ignore
          }
          return rv;
        }, "int", ["pointer", "pointer"])
      );
    }
  }

  if (opt.hookSymlinkat && !installedSymlinkat) {
    installedSymlinkat = true;
    const tag = "symlinkat";
    const symlinkatPtr = Module.findExportByName("libc.so", "symlinkat");
    if (symlinkatPtr !== null) {
      const symlinkat = new NativeFunction(symlinkatPtr, "int", ["pointer", "int", "pointer"]);
      Interceptor.replace(
        symlinkatPtr,
        new NativeCallback(function (target: NativePointer, fd: number, path: NativePointer): number {
          const rv = (symlinkat as any)(target, fd, path) as number;
          try {
            logEnabled(opt.log, tag, Memory.readUtf8String(target), Memory.readUtf8String(path));
          } catch {
            // ignore
          }
          return rv;
        }, "int", ["pointer", "int", "pointer"])
      );
    }
  }

  if (opt.hookInet && !installedInet) {
    installedInet = true;
    const inetAtonPtr = Module.findExportByName("libc.so", "inet_aton");
    const inetAddrPtr = Module.findExportByName("libc.so", "inet_addr");

    if (inetAtonPtr !== null) {
      const inetAton = new NativeFunction(inetAtonPtr, "int", ["pointer", "pointer"]);
      Interceptor.replace(
        inetAtonPtr,
        new NativeCallback(function (cp: NativePointer, inp: NativePointer): number {
          const rv = (inetAton as any)(cp, inp) as number;
          try {
            logEnabled(opt.log, "inet_aton", Memory.readUtf8String(cp));
          } catch {
            // ignore
          }
          return rv;
        }, "int", ["pointer", "pointer"])
      );
    }

    if (inetAddrPtr !== null) {
      const inetAddr = new NativeFunction(inetAddrPtr, "int", ["pointer"]);
      Interceptor.replace(
        inetAddrPtr,
        new NativeCallback(function (cp: NativePointer): number {
          const rv = (inetAddr as any)(cp) as number;
          try {
            logEnabled(opt.log, "inet_addr", Memory.readUtf8String(cp));
          } catch {
            // ignore
          }
          return rv;
        }, "int", ["pointer"])
      );
    }
  }

  if (opt.hookSocket && !installedSocket) {
    installedSocket = true;
    const socketPtr = Module.findExportByName("libc.so", "socket");
    if (socketPtr !== null) {
      const socket = new NativeFunction(socketPtr, "int", ["int", "int", "int"]);
      Interceptor.replace(
        socketPtr,
        new NativeCallback(function (domain: number, type: number, proto: number): number {
          const rv = (socket as any)(domain, type, proto) as number;
          logEnabled(opt.log, "socket", domain, type, proto, "->", rv);
          return rv;
        }, "int", ["int", "int", "int"])
      );
    }
  }

  if (opt.hookConnect && !installedConnect) {
    installedConnect = true;
    const connectPtr = Module.findExportByName("libc.so", "connect");
    if (connectPtr !== null) {
      const connect = new NativeFunction(connectPtr, "int", ["int", "pointer", "int"]);
      Interceptor.replace(
        connectPtr,
        new NativeCallback(function (fd: number, addr: NativePointer, len: number): number {
          const rv = (connect as any)(fd, addr, len) as number;
          try {
            const family = addr.readU16();
            const port = addr.add(2).readU16();
            logEnabled(opt.log, "connect", "fd:", fd, "family:", family, "port:", port, "->", rv);
          } catch {
            // ignore
          }
          return rv;
        }, "int", ["int", "pointer", "int"])
      );
    }
  }

  if (opt.hookSend && !installedSend) {
    installedSend = true;
    const sendPtr = Module.findExportByName("libc.so", "send");
    if (sendPtr !== null) {
      const send = new NativeFunction(sendPtr, "int", ["int", "pointer", "int", "int"]);
      Interceptor.replace(
        sendPtr,
        new NativeCallback(function (sockfd: number, msg: NativePointer, len: number, flags: number): number {
          const rv = (send as any)(sockfd, msg, len, flags) as number;
          try {
            logEnabled(opt.log, "send", sockfd, Memory.readUtf8String(msg, Math.min(len, 256)), len, flags);
          } catch {
            // ignore
          }
          return rv;
        }, "int", ["int", "pointer", "int", "int"])
      );
    }
  }

  if (opt.hookSendto && !installedSendto) {
    installedSendto = true;
    const sendtoPtr = Module.findExportByName("libc.so", "sendto");
    if (sendtoPtr !== null) {
      const sendto = new NativeFunction(sendtoPtr, "int", ["int", "pointer", "int", "int", "pointer", "int"]);
      Interceptor.replace(
        sendtoPtr,
        new NativeCallback(function (
          sockfd: number,
          msg: NativePointer,
          len: number,
          flags: number,
          daddr: NativePointer,
          dlen: number
        ): number {
          const rv = (sendto as any)(sockfd, msg, len, flags, daddr, dlen) as number;
          // keep log optional/noisy
          return rv;
        }, "int", ["int", "pointer", "int", "int", "pointer", "int"])
      );
    }
  }

  if (opt.hookPthreadCreate && !installedPthreadCreate) {
    installedPthreadCreate = true;
    const tag = "pthread_create";
    const pthreadCreatePtr = Module.findExportByName("libc.so", "pthread_create");
    if (pthreadCreatePtr !== null) {
      const pthreadCreate = new NativeFunction(pthreadCreatePtr, "int", ["pointer", "pointer", "pointer", "pointer"]);
      Interceptor.replace(
        pthreadCreatePtr,
        new NativeCallback(function (ptr0: NativePointer, ptr1: NativePointer, ptr2: NativePointer, ptr3: NativePointer): number {
          const rv = (pthreadCreate as any)(ptr0, ptr1, ptr2, ptr3) as number;
          // The original script logs thread entrypoints inside a chosen library. Keep as optional.
          const lib = opt.monitorLibrary;
          const base = Module.findBaseAddress(lib);
          if (base !== null) {
            try {
              const m2 = Process.getModuleByAddress(ptr2);
              if (m2.name === lib) logEnabled(opt.log, tag, "thread start:", lib, "off:", ptr2.sub(base));
            } catch {
              // ignore
            }
          }
          return rv;
        }, "int", ["pointer", "pointer", "pointer", "pointer"])
      );
    }
  }
}

export function antiAll(options: AntiAllOptions = {}): void {
  antiFrida(options.frida);
  antiDebug(options.debug);
}

export function bypassNeteaseNisMyJniLoad(options: NeteaseNisBypassOptions = {}): void {
  const log = options.log ?? true;
  const returnValue = options.returnValue ?? true;
  const retryMs = options.retryMs ?? 50;

  const className = "com.netease.nis.wrapper.MyJni";

  const tryInstall = (): void => {
    if (typeof Java === "undefined" || !Java.available) {
      setTimeout(tryInstall, retryMs);
      return;
    }

    Java.perform(() => {
      try {
        const MyJni = Java.use(className);
        const overloads = MyJni.load?.overloads ?? [];
        if (overloads.length === 0) {
          if (log) console.log("[nis] MyJni.load overloads not found");
          return;
        }
        overloads.forEach((ov) => {
          ov.implementation = function (app, s) {
            if (log) {
              let arg1 = "";
              try {
                arg1 = s ? s.toString() : "null";
              } catch {
                arg1 = "<unreadable>";
              }
              console.log("[nis] bypass MyJni.load(app, str) ->", returnValue, "arg:", arg1);
            }
            return returnValue;
          };
        });
        if (log) console.log("[nis] installed bypass for", className, "load()");
      } catch (e) {
        // Class may not be loaded yet; retry.
        setTimeout(tryInstall, retryMs);
      }
    });
  };

  tryInstall();
}
