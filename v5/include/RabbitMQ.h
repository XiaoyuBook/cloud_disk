#pragma once
#ifndef RABBITMQ_H
#define RABBITMQ_H


#include <SimpleAmqpClient/SimpleAmqpClient.h>
#include <string>
#include "nlohmann/json.hpp"
#include <iostream>
#include <fstream>
#define RABBITMQ_CONFIG_PATH "../config/RabbitMQ_config.json"

class RabbitMQ {
    public:
        explicit RabbitMQ(const std::string& config_path = "RabbitMQConfig.json");
        
        void producer(const char * content);
        void consumer();  // 声明但未实现
    
    private:
        void get_RabbitMQConfig(const std::string& config_path);
    
        std::string m_host;
        int m_port;
        std::string m_username;
        std::string m_password;
        std::string m_vhost;
        std::string m_exchange;
        std::string m_routing_key;
        std::string m_uri;
        std::string m_queue;
    };


#endif