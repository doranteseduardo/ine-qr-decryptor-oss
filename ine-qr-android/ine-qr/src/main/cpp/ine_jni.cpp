/* ══ FILE: ine_jni.cpp ══
 *
 * JNI surface for the Android library. Mirrors what ine-qr-api/main.go
 * already does via cgo:
 *
 *   1. Take a 1712-byte combined QR payload (left[2:] + right[2:]).
 *   2. run_no_so_pipeline()  → opaque decoded buffer.
 *   3. decode_to_buffers()   → (json string, webp bytes).
 *   4. Hand both back as an mx.ine.qr.IneResult.
 *
 * Errors flow as IneQr.Error.* exceptions thrown across the boundary.
 */

#include <jni.h>
#include <android/log.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "no_so_crypto.h"
#include "output_decode.h"
}

#define LOG_TAG "ine-qr"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

void throwError(JNIEnv *env, const char *innerClass, const char *msg = nullptr) {
    char fqcn[128];
    snprintf(fqcn, sizeof(fqcn), "mx/ine/qr/IneQr$Error$%s", innerClass);
    jclass cls = env->FindClass(fqcn);
    if (cls) {
        env->ThrowNew(cls, msg ? msg : "");
        env->DeleteLocalRef(cls);
    } else {
        // Fallback: a regular RuntimeException so the app never crashes
        // silently on a missing inner class.
        env->ExceptionClear();
        jclass rt = env->FindClass("java/lang/RuntimeException");
        env->ThrowNew(rt, msg ? msg : innerClass);
        env->DeleteLocalRef(rt);
    }
}

}  // namespace

extern "C"
JNIEXPORT jobject JNICALL
Java_mx_ine_qr_internal_NativeBridge_decodeCombinedNative(
        JNIEnv *env, jclass /*clazz*/, jbyteArray combinedArr) {

    if (combinedArr == nullptr) {
        throwError(env, "InvalidPayload", "combined is null");
        return nullptr;
    }

    const jsize len = env->GetArrayLength(combinedArr);
    if (len < 1712) {
        throwError(env, "InvalidPayload", "combined < 1712 bytes");
        return nullptr;
    }

    jbyte *combined = env->GetByteArrayElements(combinedArr, nullptr);
    if (!combined) {
        throwError(env, "InvalidPayload", "GetByteArrayElements failed");
        return nullptr;
    }

    uint8_t *decoded = nullptr;
    size_t decoded_len = 0;
    int rc = run_no_so_pipeline(reinterpret_cast<const uint8_t *>(combined),
                                static_cast<size_t>(len),
                                &decoded, &decoded_len);
    env->ReleaseByteArrayElements(combinedArr, combined, JNI_ABORT);

    if (rc != 0 || decoded == nullptr) {
        free(decoded);
        throwError(env, "CryptoFailure", "run_no_so_pipeline failed");
        return nullptr;
    }

    char *json = nullptr;
    size_t json_len = 0;
    uint8_t *webp = nullptr;
    size_t webp_len = 0;
    rc = decode_to_buffers(decoded, decoded_len,
                           &json, &json_len, &webp, &webp_len);
    free(decoded);

    if (rc != 0 || json == nullptr) {
        free(json);
        free(webp);
        throwError(env, "OutputDecode", "decode_to_buffers failed");
        return nullptr;
    }

    // Build the IneResult(json: String, webp: ByteArray).
    jclass resultCls = env->FindClass("mx/ine/qr/IneResult");
    jmethodID ctor = env->GetMethodID(resultCls, "<init>",
                                       "(Ljava/lang/String;[B)V");
    jstring jsonStr = env->NewStringUTF(json);
    jbyteArray webpArr = env->NewByteArray(static_cast<jsize>(webp_len));
    if (webp_len > 0) {
        env->SetByteArrayRegion(webpArr, 0, static_cast<jsize>(webp_len),
                                 reinterpret_cast<const jbyte *>(webp));
    }
    jobject result = env->NewObject(resultCls, ctor, jsonStr, webpArr);

    free(json);
    free(webp);
    env->DeleteLocalRef(jsonStr);
    env->DeleteLocalRef(webpArr);
    env->DeleteLocalRef(resultCls);
    return result;
}

/* Test-only entry point: decode an ALREADY-decrypted buffer directly.
 *
 * Skips the entire AES/RSA crypto pipeline and calls decode_to_buffers()
 * on the given buffer (2-byte BE text_len + CHAR_TABLE text + 2-byte BE
 * img_len + WebP). Lets the instrumented tests exercise JNI marshalling +
 * the bit-unpacking / WebP passthrough against a synthetic, PII-free fixture
 * without needing a real encrypted QR payload (which cannot be forged — the
 * RSA layers use recovered public keys). Not used by any production path. */
extern "C"
JNIEXPORT jobject JNICALL
Java_mx_ine_qr_internal_NativeBridge_decodeDecryptedNative(
        JNIEnv *env, jclass /*clazz*/, jbyteArray decodedArr) {

    if (decodedArr == nullptr) {
        throwError(env, "InvalidPayload", "decoded is null");
        return nullptr;
    }

    const jsize len = env->GetArrayLength(decodedArr);
    jbyte *decoded = env->GetByteArrayElements(decodedArr, nullptr);
    if (!decoded) {
        throwError(env, "InvalidPayload", "GetByteArrayElements failed");
        return nullptr;
    }

    char *json = nullptr;
    size_t json_len = 0;
    uint8_t *webp = nullptr;
    size_t webp_len = 0;
    int rc = decode_to_buffers(reinterpret_cast<const uint8_t *>(decoded),
                               static_cast<size_t>(len),
                               &json, &json_len, &webp, &webp_len);
    env->ReleaseByteArrayElements(decodedArr, decoded, JNI_ABORT);

    if (rc != 0 || json == nullptr) {
        free(json);
        free(webp);
        throwError(env, "OutputDecode", "decode_to_buffers failed");
        return nullptr;
    }

    jclass resultCls = env->FindClass("mx/ine/qr/IneResult");
    jmethodID ctor = env->GetMethodID(resultCls, "<init>",
                                       "(Ljava/lang/String;[B)V");
    jstring jsonStr = env->NewStringUTF(json);
    jbyteArray webpArr = env->NewByteArray(static_cast<jsize>(webp_len));
    if (webp_len > 0) {
        env->SetByteArrayRegion(webpArr, 0, static_cast<jsize>(webp_len),
                                 reinterpret_cast<const jbyte *>(webp));
    }
    jobject result = env->NewObject(resultCls, ctor, jsonStr, webpArr);

    free(json);
    free(webp);
    env->DeleteLocalRef(jsonStr);
    env->DeleteLocalRef(webpArr);
    env->DeleteLocalRef(resultCls);
    return result;
}
