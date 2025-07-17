#ifndef CONSUL_SERVICE_H
#define CONSUL_SERVICE_H

#include <workflow/WFTaskFactory.h>
#include <string>
#include <atomic>
#include "ppconsul/agent.h"

using ppconsul::Consul;
using namespace ppconsul::agent;
using namespace std::chrono_literals;

class ConsulService {
private:
    Consul consul;
    Agent agent;
    std::string service_id;
    std::string service_name;
    std::string service_address;
    int service_port;
    std::atomic<bool> running{false};
    int heartbeat_interval;  // 心跳间隔（秒）
    int ttl;                 // TTL超时（秒）

    // 启动心跳定时器
    void start_heartbeat_timer();

    // 心跳定时器回调函数
    static void timer_callback(WFTimerTask* task, ConsulService* self);

public:
    // 构造函数
    ConsulService(const std::string& consul_address = "http://127.0.0.1:8500",
                  const std::string& datacenter = "dc1");

    // 析构函数
    ~ConsulService();

    // 注册服务
    bool register_service(const std::string& id,
                         const std::string& name,
                         const std::string& address,
                         int port);

    // 注销服务
    void deregister_service();

    // 发送心跳
    void send_heartbeat();

    // 设置心跳间隔（秒）
    void set_heartbeat_interval(int interval);

    // 设置TTL超时（秒）
    void set_ttl(int timeout);
};

#endif // CONSUL_SERVICE_H