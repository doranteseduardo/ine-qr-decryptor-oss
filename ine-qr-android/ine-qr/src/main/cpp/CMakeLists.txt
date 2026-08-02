# ── ine-qr-android native library ─────────────────────────────────────
#
# Builds a single libine_qr_jni.so per ABI:
#   - the platform-agnostic crypto pipeline from ine-qr-c/src/no_so_crypto.c
#   - the output decoder from ine-qr-c/src/output_decode.c
#   - the OpenSSL/BoringSSL backend (crypto_backend_openssl.c reused verbatim,
#     compiled here as crypto_backend_boringssl.c — same source, BoringSSL
#     headers are API-compatible)
#   - the JNI glue (ine_jni.cpp)
#
# BoringSSL is fetched at configure time from a pinned commit. The Android
# NDK does not export BoringSSL headers in its public sysroot, and linking
# the system libcrypto.so is unstable across Android releases — vendoring
# is the only sane path for a research/portfolio repo.

cmake_minimum_required(VERSION 3.22)
project(ine_qr_jni C CXX)

set(CMAKE_C_STANDARD   17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 16 KB page size for Android 15+. The AGP 8.5 default is 4 KB.
add_link_options("-Wl,-z,max-page-size=16384")

# ── BoringSSL via FetchContent ────────────────────────────────────────
include(FetchContent)
set(BORINGSSL_TAG "0.20240930.0" CACHE STRING "BoringSSL tag")
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(OPENSSL_NO_ASM OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    boringssl
    GIT_REPOSITORY https://github.com/google/boringssl.git
    GIT_TAG        ${BORINGSSL_TAG}
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(boringssl)

# ── Source layout: pull the platform-agnostic C from ine-qr-c/ ────────
set(INE_QR_C "${CMAKE_CURRENT_LIST_DIR}/../../../../../ine-qr-c")
get_filename_component(INE_QR_C "${INE_QR_C}" ABSOLUTE)

if(NOT EXISTS "${INE_QR_C}/src/no_so_crypto.c")
    message(FATAL_ERROR "ine-qr-c source tree not found at ${INE_QR_C}")
endif()

add_library(ine_qr_jni SHARED
    "${INE_QR_C}/src/no_so_crypto.c"
    "${INE_QR_C}/src/output_decode.c"
    "${INE_QR_C}/vendor/base64.c"
    crypto_backend_boringssl.c
    ine_jni.cpp
)

target_include_directories(ine_qr_jni PRIVATE
    "${INE_QR_C}/include"
    "${INE_QR_C}/vendor"
    "${CMAKE_CURRENT_LIST_DIR}"
)

target_link_libraries(ine_qr_jni PRIVATE
    crypto       # BoringSSL static, exposed by FetchContent
    log
    android
)

target_compile_options(ine_qr_jni PRIVATE
    -Wall -Wextra -Wno-unused-parameter -O2
)
