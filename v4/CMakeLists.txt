# 设置CMake的最小版本
cmake_minimum_required(VERSION 3.15)

# 项目名称
project(CloudDisk)

# 指定C++版本
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置输出路径
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../)

# ProtoBuf / SRPC 编译生成的文件
set(PROTO_SRCS
    cloud_disk_service.pb.cc
    cloud_disk_service.pb.h
    cloud_disk_service.srpc.h
)

# 公共源文件
set(COMMON_SRCS
    CryptoUtil.cc
    OSSManager.cc
    RabbitMQ.cc
)

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

# 公共链接库
set(COMMON_LIBS
    crypto
    ssl
    jwt
    workflow
    wfrest
    alibabacloud-oss-cpp-sdk
    curl
    pthread
    protobuf
    srpc
    snappy
    lz4
    ${SIMPLE_AMQP_CLIENT_LIB}
    ${Boost_LIBRARIES}
)

# ========== 主服务 ==========
add_executable(server
    CloudiskServer.cpp
    main.cpp
    ${COMMON_SRCS}
    ${PROTO_SRCS}
)

target_link_libraries(server PRIVATE ${COMMON_LIBS})

# ========== SRPC 服务端 ==========
add_executable(rpc_server
    server.pb_skeleton.cc
    ${COMMON_SRCS}
    cloud_disk_service.pb.cc
)

target_link_libraries(rpc_server PRIVATE ${COMMON_LIBS})

# ========== SRPC 客户端（带 CloudiskServer） ==========
add_executable(rpc_client
    main.cpp
    CloudiskServer.cpp   # 关键点：加入 CloudiskServer.cpp
    ${COMMON_SRCS}
    cloud_disk_service.pb.cc
)

target_link_libraries(rpc_client PRIVATE ${COMMON_LIBS})
