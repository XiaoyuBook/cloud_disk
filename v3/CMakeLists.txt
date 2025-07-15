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
)

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
)
