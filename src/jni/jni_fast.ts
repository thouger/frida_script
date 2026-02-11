//@ts-nocheck

const JNI_STRUCT_ARRAY = [
  "reserved0",
  "reserved1",
  "reserved2",
  "reserved3",
  "GetVersion",
  "DefineClass",
  "FindClass",
  "FromReflectedMethod",
  "FromReflectedField",
  "ToReflectedMethod",
  "GetSuperclass",
  "IsAssignableFrom",
  "ToReflectedField",
  "Throw",
  "ThrowNew",
  "ExceptionOccurred",
  "ExceptionDescribe",
  "ExceptionClear",
  "FatalError",
  "PushLocalFrame",
  "PopLocalFrame",
  "NewGlobalRef",
  "DeleteGlobalRef",
  "DeleteLocalRef",
  "IsSameObject",
  "NewLocalRef",
  "EnsureLocalCapacity",
  "AllocObject",
  "NewObject",
  "NewObjectV",
  "NewObjectA",
  "GetObjectClass",
  "IsInstanceOf",
  "GetMethodID",
  "CallObjectMethod",
  "CallObjectMethodV",
  "CallObjectMethodA",
  "CallBooleanMethod",
  "CallBooleanMethodV",
  "CallBooleanMethodA",
  "CallByteMethod",
  "CallByteMethodV",
  "CallByteMethodA",
  "CallCharMethod",
  "CallCharMethodV",
  "CallCharMethodA",
  "CallShortMethod",
  "CallShortMethodV",
  "CallShortMethodA",
  "CallIntMethod",
  "CallIntMethodV",
  "CallIntMethodA",
  "CallLongMethod",
  "CallLongMethodV",
  "CallLongMethodA",
  "CallFloatMethod",
  "CallFloatMethodV",
  "CallFloatMethodA",
  "CallDoubleMethod",
  "CallDoubleMethodV",
  "CallDoubleMethodA",
  "CallVoidMethod",
  "CallVoidMethodV",
  "CallVoidMethodA",
  "CallNonvirtualObjectMethod",
  "CallNonvirtualObjectMethodV",
  "CallNonvirtualObjectMethodA",
  "CallNonvirtualBooleanMethod",
  "CallNonvirtualBooleanMethodV",
  "CallNonvirtualBooleanMethodA",
  "CallNonvirtualByteMethod",
  "CallNonvirtualByteMethodV",
  "CallNonvirtualByteMethodA",
  "CallNonvirtualCharMethod",
  "CallNonvirtualCharMethodV",
  "CallNonvirtualCharMethodA",
  "CallNonvirtualShortMethod",
  "CallNonvirtualShortMethodV",
  "CallNonvirtualShortMethodA",
  "CallNonvirtualIntMethod",
  "CallNonvirtualIntMethodV",
  "CallNonvirtualIntMethodA",
  "CallNonvirtualLongMethod",
  "CallNonvirtualLongMethodV",
  "CallNonvirtualLongMethodA",
  "CallNonvirtualFloatMethod",
  "CallNonvirtualFloatMethodV",
  "CallNonvirtualFloatMethodA",
  "CallNonvirtualDoubleMethod",
  "CallNonvirtualDoubleMethodV",
  "CallNonvirtualDoubleMethodA",
  "CallNonvirtualVoidMethod",
  "CallNonvirtualVoidMethodV",
  "CallNonvirtualVoidMethodA",
  "GetFieldID",
  "GetObjectField",
  "GetBooleanField",
  "GetByteField",
  "GetCharField",
  "GetShortField",
  "GetIntField",
  "GetLongField",
  "GetFloatField",
  "GetDoubleField",
  "SetObjectField",
  "SetBooleanField",
  "SetByteField",
  "SetCharField",
  "SetShortField",
  "SetIntField",
  "SetLongField",
  "SetFloatField",
  "SetDoubleField",
  "GetStaticMethodID",
  "CallStaticObjectMethod",
  "CallStaticObjectMethodV",
  "CallStaticObjectMethodA",
  "CallStaticBooleanMethod",
  "CallStaticBooleanMethodV",
  "CallStaticBooleanMethodA",
  "CallStaticByteMethod",
  "CallStaticByteMethodV",
  "CallStaticByteMethodA",
  "CallStaticCharMethod",
  "CallStaticCharMethodV",
  "CallStaticCharMethodA",
  "CallStaticShortMethod",
  "CallStaticShortMethodV",
  "CallStaticShortMethodA",
  "CallStaticIntMethod",
  "CallStaticIntMethodV",
  "CallStaticIntMethodA",
  "CallStaticLongMethod",
  "CallStaticLongMethodV",
  "CallStaticLongMethodA",
  "CallStaticFloatMethod",
  "CallStaticFloatMethodV",
  "CallStaticFloatMethodA",
  "CallStaticDoubleMethod",
  "CallStaticDoubleMethodV",
  "CallStaticDoubleMethodA",
  "CallStaticVoidMethod",
  "CallStaticVoidMethodV",
  "CallStaticVoidMethodA",
  "GetStaticFieldID",
  "GetStaticObjectField",
  "GetStaticBooleanField",
  "GetStaticByteField",
  "GetStaticCharField",
  "GetStaticShortField",
  "GetStaticIntField",
  "GetStaticLongField",
  "GetStaticFloatField",
  "GetStaticDoubleField",
  "SetStaticObjectField",
  "SetStaticBooleanField",
  "SetStaticByteField",
  "SetStaticCharField",
  "SetStaticShortField",
  "SetStaticIntField",
  "SetStaticLongField",
  "SetStaticFloatField",
  "SetStaticDoubleField",
  "NewString",
  "GetStringLength",
  "GetStringChars",
  "ReleaseStringChars",
  "NewStringUTF",
  "GetStringUTFLength",
  "GetStringUTFChars",
  "ReleaseStringUTFChars",
  "GetArrayLength",
  "NewObjectArray",
  "GetObjectArrayElement",
  "SetObjectArrayElement",
  "NewBooleanArray",
  "NewByteArray",
  "NewCharArray",
  "NewShortArray",
  "NewIntArray",
  "NewLongArray",
  "NewFloatArray",
  "NewDoubleArray",
  "GetBooleanArrayElements",
  "GetByteArrayElements",
  "GetCharArrayElements",
  "GetShortArrayElements",
  "GetIntArrayElements",
  "GetLongArrayElements",
  "GetFloatArrayElements",
  "GetDoubleArrayElements",
  "ReleaseBooleanArrayElements",
  "ReleaseByteArrayElements",
  "ReleaseCharArrayElements",
  "ReleaseShortArrayElements",
  "ReleaseIntArrayElements",
  "ReleaseLongArrayElements",
  "ReleaseFloatArrayElements",
  "ReleaseDoubleArrayElements",
  "GetBooleanArrayRegion",
  "GetByteArrayRegion",
  "GetCharArrayRegion",
  "GetShortArrayRegion",
  "GetIntArrayRegion",
  "GetLongArrayRegion",
  "GetFloatArrayRegion",
  "GetDoubleArrayRegion",
  "SetBooleanArrayRegion",
  "SetByteArrayRegion",
  "SetCharArrayRegion",
  "SetShortArrayRegion",
  "SetIntArrayRegion",
  "SetLongArrayRegion",
  "SetFloatArrayRegion",
  "SetDoubleArrayRegion",
  "RegisterNatives",
  "UnregisterNatives",
  "MonitorEnter",
  "MonitorExit",
  "GetJavaVM",
  "GetStringRegion",
  "GetStringUTFRegion",
  "GetPrimitiveArrayCritical",
  "ReleasePrimitiveArrayCritical",
  "GetStringCritical",
  "ReleaseStringCritical",
  "NewWeakGlobalRef",
  "DeleteWeakGlobalRef",
  "ExceptionCheck",
  "NewDirectByteBuffer",
  "GetDirectBufferAddress",
  "GetDirectBufferCapacity",
  "GetObjectRefType",
];

const CLS_BYTE_ARRAY = Memory.allocUtf8String("[B");
const CLS_OBJECT_ARRAY = Memory.allocUtf8String("[Ljava/lang/Object;");
const NULL_PTR = ptr(0);

const apiCache = new Map();

function isLikelyCodePtr(p) {
  try {
    const r = Process.findRangeByAddress(ptr(p));
    return !!r && typeof r.protection === "string" && r.protection.indexOf("x") !== -1;
  } catch (_) {
    return false;
  }
}

export function getJniTablePtr(envPtr) {
  try {
    const env = ptr(envPtr);
    const p1 = env.readPointer();
    const f1 = p1.add(Process.pointerSize * JNI_STRUCT_ARRAY.indexOf("GetStringUTFChars")).readPointer();
    if (isLikelyCodePtr(f1)) return p1;
  } catch (_) {}

  try {
    const p0 = ptr(envPtr);
    const f0 = p0.add(Process.pointerSize * JNI_STRUCT_ARRAY.indexOf("GetStringUTFChars")).readPointer();
    if (isLikelyCodePtr(f0)) return p0;
  } catch (_) {}

  return null;
}

function jniIndex(nameOrIndex) {
  if (typeof nameOrIndex === "number") return nameOrIndex | 0;
  if (!nameOrIndex) return -1;
  return JNI_STRUCT_ARRAY.indexOf(String(nameOrIndex));
}

export function getJniApi(envPtr, opts) {
  const table = getJniTablePtr(envPtr);
  if (!table) return null;
  const key = table.toString();
  const cached = apiCache.get(key);
  if (cached) return cached;

  const fnCache = new Map();
  const api = {
    table,
    index: (name) => jniIndex(name),
    ptr: (nameOrIndex) => {
      const idx = jniIndex(nameOrIndex);
      if (idx < 0) return NULL_PTR;
      return table.add(Process.pointerSize * idx).readPointer();
    },
    fn: (nameOrIndex, retType, argTypes) => {
      const idx = jniIndex(nameOrIndex);
      if (idx < 0) return null;
      const sigKey = `${idx}|${retType}|${(argTypes || []).join(",")}`;
      const got = fnCache.get(sigKey);
      if (got) return got;
      const p = table.add(Process.pointerSize * idx).readPointer();
      if (!p || ptr(p).isNull() || !isLikelyCodePtr(p)) return null;
      const nf = new NativeFunction(p, retType, argTypes || []);
      fnCache.set(sigKey, nf);
      return nf;
    },
  };

  apiCache.set(key, api);
  if (opts?.logInit) {
    try {
      const pGetStringUTFChars = api.ptr("GetStringUTFChars");
      const pGetArrayLength = api.ptr("GetArrayLength");
      const pFindClass = api.ptr("FindClass");
      const pIsInstanceOf = api.ptr("IsInstanceOf");
      console.log(
        `[jni] init ok: table=${table} GetStringUTFChars=${pGetStringUTFChars} GetArrayLength=${pGetArrayLength} FindClass=${pFindClass} IsInstanceOf=${pIsInstanceOf}`
      );
    } catch (_) {
      console.log(`[jni] init ok: table=${table}`);
    }
  }
  return api;
}

function clearExceptionIfAny(envPtr, api) {
  try {
    const ExceptionCheck = api.fn("ExceptionCheck", "uchar", ["pointer"]);
    const ExceptionClear = api.fn("ExceptionClear", "void", ["pointer"]);
    if (!ExceptionCheck || !ExceptionClear) return;
    if (ExceptionCheck(ptr(envPtr))) ExceptionClear(ptr(envPtr));
  } catch (_) {}
}

function deleteLocalRef(envPtr, api, obj) {
  try {
    const DeleteLocalRef = api.fn("DeleteLocalRef", "void", ["pointer", "pointer"]);
    if (!DeleteLocalRef) return;
    const p = ptr(obj);
    if (p.isNull()) return;
    DeleteLocalRef(ptr(envPtr), p);
  } catch (_) {}
}

function findClassLocal(envPtr, api, classDescPtr) {
  try {
    const FindClass = api.fn("FindClass", "pointer", ["pointer", "pointer"]);
    if (!FindClass) return null;
    const cls = FindClass(ptr(envPtr), classDescPtr);
    if (!cls || ptr(cls).isNull()) return null;
    return ptr(cls);
  } catch (_) {
    return null;
  }
}

function isInstanceOf(envPtr, api, obj, cls) {
  try {
    const IsInstanceOf = api.fn("IsInstanceOf", "uchar", ["pointer", "pointer", "pointer"]);
    if (!IsInstanceOf) return false;
    if (!obj) return false;
    return !!IsInstanceOf(ptr(envPtr), ptr(obj), cls);
  } catch (_) {
    return false;
  }
}

export function readJString(envPtr, jstringHandle) {
  if (!jstringHandle) return null;
  const api = getJniApi(envPtr);
  if (!api) return null;
  const GetStringUTFChars = api.fn("GetStringUTFChars", "pointer", ["pointer", "pointer", "pointer"]);
  const ReleaseStringUTFChars = api.fn("ReleaseStringUTFChars", "void", ["pointer", "pointer", "pointer"]);
  if (!GetStringUTFChars || !ReleaseStringUTFChars) return null;
  try {
    const chars = GetStringUTFChars(ptr(envPtr), ptr(jstringHandle), NULL_PTR);
    if (!chars || ptr(chars).isNull()) return null;
    const s = ptr(chars).readCString();
    ReleaseStringUTFChars(ptr(envPtr), ptr(jstringHandle), ptr(chars));
    return s;
  } catch (_) {
    return null;
  }
}

export function getByteArrayLength(envPtr, jarrayHandle) {
  if (!jarrayHandle) return -1;
  const api = getJniApi(envPtr);
  if (!api) return -1;
  const GetArrayLength = api.fn("GetArrayLength", "int", ["pointer", "pointer"]);
  if (!GetArrayLength) return -1;
  try {
    return GetArrayLength(ptr(envPtr), ptr(jarrayHandle)) | 0;
  } catch (_) {
    return -1;
  }
}

function isJByteArray(envPtr, api, objHandle) {
  const cls = findClassLocal(envPtr, api, CLS_BYTE_ARRAY);
  if (!cls) return false;
  const ok = isInstanceOf(envPtr, api, objHandle, cls);
  deleteLocalRef(envPtr, api, cls);
  return ok;
}

function isJObjectArray(envPtr, api, objHandle) {
  const cls = findClassLocal(envPtr, api, CLS_OBJECT_ARRAY);
  if (!cls) return false;
  const ok = isInstanceOf(envPtr, api, objHandle, cls);
  deleteLocalRef(envPtr, api, cls);
  return ok;
}

export function getBodyByteArrayLengthFromArg(envPtr, objHandle) {
  const api = getJniApi(envPtr);
  if (!api) return -1;

  try {
    if (isJByteArray(envPtr, api, objHandle)) return getByteArrayLength(envPtr, objHandle);

    const GetObjectArrayElement = api.fn("GetObjectArrayElement", "pointer", ["pointer", "pointer", "int"]);
    if (!GetObjectArrayElement) return -1;
    if (!isJObjectArray(envPtr, api, objHandle)) return -1;

    const elem0 = GetObjectArrayElement(ptr(envPtr), ptr(objHandle), 0);
    clearExceptionIfAny(envPtr, api);
    if (!elem0 || ptr(elem0).isNull()) return -1;

    const len = isJByteArray(envPtr, api, elem0) ? getByteArrayLength(envPtr, elem0) : -1;
    deleteLocalRef(envPtr, api, elem0);
    return len;
  } catch (_) {
    clearExceptionIfAny(envPtr, api);
    return -1;
  }
}
