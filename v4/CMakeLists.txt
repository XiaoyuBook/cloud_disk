# 设置CMake的最小版本
cmake_minimum_required(VERSION 3.15)

# 项目名称
project(CloudDisk)

# 指定C++版本
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置输出路径
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)

# 设置源文件目录
set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)

# 查找 Protocol Buffers
find_package(Protobuf REQUIRED)
if(NOT Protobuf_FOUND)
    message(FATAL_ERROR "Protobuf library not found")
endif()

# 查找 SimpleAmqpClient 库
find_library(SIMPLE_AMQP_CLIENT_LIB SimpleAmqpClient)
if(NOT SIMPLE_AMQP_CLIENT_LIB)
    message(FATAL_ERROR "SimpleAmqpClient library not found")
endif()

# 查找 Boost
find_package(Boost REQUIRED COMPONENTS system)
if(NOT Boost_FOUND)
    message(FATAL_ERROR "Boost library not found")
endif()

# 查找其他依赖库
find_package(OpenSSL REQUIRED)
find_package(workflow REQUIRED)
find_package(wfrest REQUIRED)

# 设置包含目录
include_directories(
    ${INCLUDE_DIR}
    ${Protobuf_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

# 公共源文件
set(COMMON_SRCS
    ${SRC_DIR}/CryptoUtil.cc
    ${SRC_DIR}/OSSManager.cc
    ${SRC_DIR}/RabbitMQ.cc
)

# 公共链接库
set(COMMON_LIBS
    ${Protobuf_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    jwt
    workflow
    wfrest
    alibabacloud-oss-cpp-sdk
    curl
    pthread
    srpc
    snappy
    lz4
    ${SIMPLE_AMQP_CLIENT_LIB}
    ${Boost_LIBRARIES}
)

target_include_directories(server PRIVATE ${INCLUDE_DIR})
target_link_libraries(server PRIVATE ${COMMON_LIBS})

# ========== SRPC 服务端 ==========
add_executable(rpc_server
    ${SRC_DIR}/server.pb_skeleton.cc
    ${COMMON_SRCS}
    ${SRC_DIR}/cloud_disk_service.pb.cc
)

target_include_directories(rpc_server PRIVATE ${INCLUDE_DIR})
target_link_libraries(rpc_server PRIVATE ${COMMON_LIBS})

# ========== SRPC 客户端 ==========
add_executable(rpc_client
    ${SRC_DIR}/main.cpp
    ${SRC_DIR}/CloudiskServer.cpp
    ${COMMON_SRCS}
    ${SRC_DIR}/cloud_disk_service.pb.cc
)

target_include_directories(rpc_client PRIVATE ${INCLUDE_DIR})
target_link_libraries(rpc_client PRIVATE ${COMMON_LIBS})

# 安装目标到bin目录
install(TARGETS server rpc_server rpc_client
    RUNTIME DESTINATION ${PROJECT_SOURCE_DIR}/bin
)