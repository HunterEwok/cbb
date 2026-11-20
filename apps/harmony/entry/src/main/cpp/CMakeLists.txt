# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# libcbb_napi.so, the app's Node-API module over the Rust core. The core's
# static library comes from ffi/bind.sh harmony (apps/harmony/build.sh puts
# it in apps/harmony/build/ffi); CBB_FFI_DIR points elsewhere.
cmake_minimum_required(VERSION 3.16)
project(cbb_napi CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(REPO ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../..)
set(CBB_FFI_DIR ${REPO}/apps/harmony/build/ffi CACHE PATH "the directory ffi/bind.sh harmony wrote")

add_library(cbb_napi SHARED napi_init.cpp keys.cpp der.cpp)
target_include_directories(cbb_napi PRIVATE ${REPO}/ffi/include)
# The SDK's toolchain file passes flags clang leaves unused.
target_compile_options(cbb_napi PRIVATE -Wall -Wextra -Werror -Wno-unused-command-line-argument)
target_link_libraries(cbb_napi PRIVATE
    ${CBB_FFI_DIR}/${OHOS_ARCH}/libcbb_ffi.a
    libace_napi.z.so
    libhuks_ndk.z.so)
# The core's archive is large; keep only what the module calls.
target_link_options(cbb_napi PRIVATE -Wl,--gc-sections -Wl,--exclude-libs,ALL)
