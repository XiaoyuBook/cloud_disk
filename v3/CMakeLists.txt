# 设置CMake的最小版本
cmake_minimum_required(VERSION 3.15)

# 项目名称
project(CloudDisk)

# 指定C++的版本: -std=c++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置可执行程序生成的路径
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../)

# 添加可执行程序并指定源文件
add_executable(server
    CloudiskServer.cpp
    main.cpp
    CryptoUtil.cc
    OSSManager.cc
    RabbitMQ.cc      
)

# 查找SimpleAmqpClient库
find_library(SIMPLE_AMQP_CLIENT_LIB SimpleAmqpClient)
if(NOT SIMPLE_AMQP_CLIENT_LIB)
    message(FATAL_ERROR "SimpleAmqpClient library not found")
endif()

# 查找Boost库
find_package(Boost REQUIRED COMPONENTS system)
if(NOT Boost_FOUND)
    message(FATAL_ERROR "Boost library not found")
endif()

# 可能需要添加SimpleAmqpClient的头文件搜索路径
# include_directories(/path/to/simpleamqpclient/include)

# 链接库
target_link_libraries(server PRIVATE 
    crypto
    ssl
    jwt
    workflow
    wfrest
    alibabacloud-oss-cpp-sdk
    curl
    pthread
    ${SIMPLE_AMQP_CLIENT_LIB}  # 添加SimpleAmqpClient库
    ${Boost_LIBRARIES}         # 添加Boost库
)