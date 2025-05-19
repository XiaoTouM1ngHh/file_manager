cmake_minimum_required(VERSION 3.10)
project(FileManagerAPI VERSION 1.0.0 LANGUAGES CXX)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 使用vcpkg包管理器查找第三方库
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()

# 查找OpenSSL
find_package(OpenSSL REQUIRED)
if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL library not found!")
endif()

# 查找nlohmann/json（可选）
option(USE_NLOHMANN_JSON "使用nlohmann/json库来解析JSON文件" ON)
if(USE_NLOHMANN_JSON)
    find_path(NLOHMANN_JSON_INCLUDE_DIRS "nlohmann/json.hpp")
    if(NLOHMANN_JSON_INCLUDE_DIRS)
        add_compile_definitions(USE_NLOHMANN_JSON)
        message(STATUS "将使用nlohmann/json库解析JSON文件")
    else()
        message(WARNING "未找到nlohmann/json库，将使用简单的JSON解析方法")
    endif()
endif()

# 设置包含路径
include_directories(${OPENSSL_INCLUDE_DIR})
if(NLOHMANN_JSON_INCLUDE_DIRS)
    include_directories(${NLOHMANN_JSON_INCLUDE_DIRS})
endif()

# 添加示例程序
add_executable(TripleDESExample TripleDESExample.cpp)
target_link_libraries(TripleDESExample 
    PRIVATE OpenSSL::SSL OpenSSL::Crypto
)

# 添加安装规则
install(TARGETS TripleDESExample
        RUNTIME DESTINATION bin)
        
install(FILES 
        TripleDESDecryptor.hpp
        DESTINATION include)

# 显示配置信息
message(STATUS "")
message(STATUS "=== 3DES解密器配置信息 ===")
message(STATUS "OpenSSL版本: ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include目录: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL SSL库: ${OPENSSL_SSL_LIBRARY}")
message(STATUS "OpenSSL Crypto库: ${OPENSSL_CRYPTO_LIBRARY}")
if(NLOHMANN_JSON_INCLUDE_DIRS)
    message(STATUS "nlohmann/json include目录: ${NLOHMANN_JSON_INCLUDE_DIRS}")
else()
    message(STATUS "nlohmann/json: 未找到，将使用简单JSON解析")
endif()
message(STATUS "===========================")
message(STATUS "") 