//@ts-nocheck
import { native_hook } from "./so/hook_func.js";
import { toHex } from "./so/BufferUtils.js";
import { bypassVpnDetection } from "./java/vpn.js";
import { bypassSslPinning } from "./cert/sslpinning2.js";

/**
 * 读取 “X8(outptr)” 写入的最终 bytes。
 *
 * 注意：这里的 `outptr` 指的是 x8（写出参数）本身，它是一个 “指向输出对象指针的地址”，需要先解引用一次：
 *   output = *outptr
 * 然后按结构取 size/data：
 *   size = *(output + 0x0C)
 *   data = *(output + 0x10)
 *
 * 这套读法既适用于 `protobuf_serialize(0x1A86EC)`，也适用于
 * `metasec_vm_encrypt_pack_to_outptr(0x1A883C)`（旧名 `protobuf_serialize_to_outptr`）。
 */
function readBytesFromOutptr(outptr: NativePointer): { len: number; data: NativePointer; bytes: Uint8Array } | null {
  try {
    if (!outptr || outptr.isNull()) return null;

    const output = outptr.readPointer();
    if (!output || output.isNull()) return null;

    const len = output.add(0x0c).readU32();
    // 防止意外读到异常长度导致卡死/崩溃
    if (len <= 0 || len > 0x200000) return null;
    const data = output.add(0x10).readPointer();
    if (!data || data.isNull() || len === 0) return null;

    const ab = Memory.readByteArray(data, len);
    if (ab === null) return null;
    return { len, data, bytes: new Uint8Array(ab as ArrayBuffer) };
  } catch (_) {
    return null;
  }
}

// // 启用 VPN 检测绕过
// console.log("[*] 启用 VPN 检测绕过...");
// bypassVpnDetection();

// // 启用 SSL Pinning 绕过
// console.log("[*] 启用 SSL Pinning 绕过...");
// bypassSslPinning();

/**
 * 打印“加密前”的原始 protobuf 序列化 bytes。
 *
 * 背景：`metasec_vm_encrypt_pack_to_outptr(0x1A883C)`（旧名 `protobuf_serialize_to_outptr`）内部会走 `metasec_crypto_vm_dispatch(0xC7C80)`，
 * 输出很可能已被加密/封包/混淆，直接按 protobuf 反序列化会失败。
 *
 * 因此这里改为 hook `protobuf_serialize(0x1A86EC)`：它是纯 protobuf message -> bytes 的序列化点。
 * 注意：IDA 的 xref 有时会落在函数内部指令（例如 `0x1A8754`），但 Frida hook 需要用函数入口（这里是 `0x1A86EC`）。
 */
(function hookMssdkPlainProtobuf() {
  const soName = "libmetasec_ml.so";

  // protobuf_serialize (protobuf message -> bytes)
  const kProtobufSerialize = 0x1a86ec;

  // 只打大包，避免刷屏（按需要调小/调大）
  const kMinLen = 200;
  const kMaxLen = 0x200000;

  native_hook(soName, kProtobufSerialize, {
    logEnter: false,
    logLeave: false,
    customEnter(args, context, thisContext, base_addr, hook_addr, tid) {
      // outptr 在 X8（不是 x0-x7 的 args 里）
      thisContext.outptr = ptr(context.x8);
      thisContext.lr_off = ptr(context.lr).sub(base_addr).toUInt32();
    },
    customLeave(args, context, thisContext, base_addr, hook_addr, retval) {
      const parsed = readBytesFromOutptr(thisContext.outptr);
      if (!parsed) {
        // 这里不要太吵；如果你需要排查，再把这行打开
        // console.log(`[MSSDK][PB] readBytesFromOutptr failed. outptr=${thisContext.outptr}`);
        return;
      }
    //   if (parsed.len < kMinLen || parsed.len > kMaxLen) return;

      const hex = toHex(parsed.bytes);
      console.log(`[MSSDK][PB] caller_off=+0x${thisContext.lr_off.toString(16)} data=${parsed.data} len=${parsed.len}`);
      console.log(`[MSSDK][PB] hex=${hex}`);
    }
  });
})();
