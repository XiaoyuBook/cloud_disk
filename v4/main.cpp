// main.cpp
#include <iostream>
#include <signal.h>

#include "RabbitMQ.h"
#include "CloudiskServer.h"

WFFacilities::WaitGroup g_waitGroup { 1 };

void sig_handler(int)
{
    g_waitGroup.done();
}

int main()
{

    signal(SIGINT, sig_handler);

    CloudiskServer svr;
    RabbitMQ ra("RabbitMQ_config.json");
    std::thread consumer_thread([&](){
        ra.consumer();
    });
    consumer_thread.detach();

    
    // 注册路由
    svr.register_modules();

    if (svr.track().start(9527) == 0) {
        svr.list_routes();
        g_waitGroup.wait();
        svr.stop();
    } else {
        std::cerr << "Error: server start failed!\n";
    }
}
