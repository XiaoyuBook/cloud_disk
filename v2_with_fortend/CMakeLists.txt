# 设置CMake的最小版本
cmake_minimum_required(VERSION 3.15)

# 项目名称
#   项目可以包含多个目标(target)
#   target: 可执行程序, 静态库, 动态库
project(CloudDisk)

# 指定C++的版本: -std=c++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置可执行程序生成的路径
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../)

# 生成的可执行程序
add_executable(server
    CloudiskServer.cpp
    main.cpp
    CryptoUtil.cc
)

# -lcrypto -lssl -ljwt -lwfrest
target_link_libraries(server PRIVATE 
    crypto
    ssl
    jwt
    workflow
    wfrest
    ssl
    jwt
    alibabacloud-oss-cpp-sdk
    curl 
    pthread
)

