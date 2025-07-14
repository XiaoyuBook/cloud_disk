cmake_minimum_required(VERSION 3.15)

project(oss_workflow_server)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置可执行文件的输出目录
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../)

# 添加源码文件
set(SOURCE_FILES
    main.cc
    CryptoUtil.cc
)

# 添加可执行程序 target 名为 server
add_executable(server ${SOURCE_FILES})

# 编译选项
target_compile_options(server PRIVATE
    -fno-rtti
    -g
)

# 链接库
target_link_libraries(server PRIVATE 
    workflow
    wfrest
    ssl
    crypto
    jwt
    alibabacloud-oss-cpp-sdk
    curl 
    pthread
)
