cmake_minimum_required(VERSION 3.10)
project(tee_provider_demo)

# 设置C标准
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 启用调试信息
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# 如果没有指定构建类型，默认使用Debug
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# 查找OpenSSL
find_package(OpenSSL 3.0 REQUIRED)

# 查找Threads (for pthread)
find_package(Threads REQUIRED)

# 包含目录
include_directories(${OPENSSL_INCLUDE_DIR})

# 设置编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter")

# TEE Provider库
add_library(tee_provider SHARED
    tee_provider.c
    tee_provider.h
)

target_link_libraries(tee_provider
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

# 设置TEE Provider库的属性
set_target_properties(tee_provider PROPERTIES
    VERSION 1.0.0
    SOVERSION 1
    PUBLIC_HEADER tee_provider.h
)

# TLS客户端
add_executable(tls_client
    tls_client.c
)

target_link_libraries(tls_client
    tee_provider
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

# 测试服务器
add_executable(test_server
    test_server.c
)

target_link_libraries(test_server
    ${OPENSSL_LIBRARIES}
    Threads::Threads
)

# 安装配置
install(TARGETS tee_provider tls_client test_server
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include
)

# 添加自定义目标来生成证书
add_custom_target(generate_certs
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/generate_certs.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating test certificates"
)

# 添加测试目标
enable_testing()

# 基本构建测试
add_test(NAME build_test
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target all
)

# 证书生成测试
add_test(NAME cert_generation_test
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/generate_certs.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# 库加载测试
add_test(NAME library_test
    COMMAND ldd $<TARGET_FILE:tls_client>
)

# 打印构建信息
message(STATUS "TEE Provider Demo Configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "  OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "  OpenSSL libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")

# 添加编译后的提示
add_custom_command(TARGET tls_client POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo ""
    COMMAND ${CMAKE_COMMAND} -E echo "=== 编译完成 ==="
    COMMAND ${CMAKE_COMMAND} -E echo "生成证书: make generate_certs 或 ./generate_certs.sh"
    COMMAND ${CMAKE_COMMAND} -E echo "启动服务器: ./test_server [port]"
    COMMAND ${CMAKE_COMMAND} -E echo "运行客户端: ./tls_client [host] [port]"
    COMMAND ${CMAKE_COMMAND} -E echo ""
)