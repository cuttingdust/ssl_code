cmake_minimum_required(VERSION 3.12)

# 使用 vcpkg 工具链文件 Warning  工具连设置必须是在project 前面
set(CMAKE_TOOLCHAIN_FILE $ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake CACHE STRING "Vcpkg toolchain file")
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

project(ssl-code)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
if(MSVC)
set(CMAKE_GENERATOR_PLATFORM x64)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_BUILD_TYPE Debug) 

# OpenSSL
find_package(OpenSSL REQUIRED)
message("OpenSSL_FOUND = ${OpenSSL_FOUND}")

#libevent
find_package(Libevent CONFIG REQUIRED)
message("Libevent_FOUND = ${Libevent_FOUND}")


# OpenMP
find_package(OpenMP)
message("OpenMP_FOUND = ${OpenMP_FOUND}")

if(OpenMP_FOUND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")
endif()

# 外部依赖项
set(DPS_INCLUDES)
set(DPS_TARGETS)
set(DPS_LIBRARYS)

# 资源文件

# #图标
set(RC_FILE)

# 忽略特定库
if(MSVC)
SET(CMAKE_EXE_LINKER_FLAGS /NODEFAULTLIB:"libcmt.lib;libc.lib")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CommonTools)


add_subdirectory(test_ssl)
add_subdirectory(base16)
add_subdirectory(base64)
add_subdirectory(base58)
add_subdirectory(MD5_test_hash)
add_subdirectory(MD5_hash_list)
add_subdirectory(SA1_merkle_hash)
add_subdirectory(SA256_test_bit)
add_subdirectory(SA3_and_sm3_test)
add_subdirectory(HMAC_test)
add_subdirectory(XorCipher)
add_subdirectory(XorDes)
add_subdirectory(XorDes_EBC)
add_subdirectory(XorDes_CBC)
add_subdirectory(XSec)
add_subdirectory(Xor3DES_EDE)
add_subdirectory(Xor3DES_FILE)
add_subdirectory(XorRSA)
add_subdirectory(XorRSA_EVP)
add_subdirectory(XorRSA_ECC)
add_subdirectory(XorRSA_ECDH)
add_subdirectory(XorTLS)
add_subdirectory(XorTLS_HTTPS)
add_subdirectory(XorTLS_EVENT)

# 拷贝assert目录到输出目录
set(ASSERT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/assert)

file(COPY ${ASSERT_PATH} DESTINATION ${OUT_RUN_PATH})
