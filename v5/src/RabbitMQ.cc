#include "../include/RabbitMQ.h"
#include "../include/OSSManager.h"
using json = nlohmann::json;
using std::string;


RabbitMQ::RabbitMQ(const std::string& config_path) {
    get_RabbitMQConfig(config_path);
}


void RabbitMQ::get_RabbitMQConfig(const std::string& config_path) {
        std::ifstream ifs(config_path);  
        if (!ifs.is_open()) {
            std::cout << "无法打开配置文件" << std::endl;
            return;
        }

        json config = json::parse(ifs); 
        m_host = config["host"];
        m_port = config["port"];
        m_username = config["username"];
        m_password = config["password"];
        m_vhost = config["vhost"];
        m_exchange = config["exchange"];
        m_routing_key = config["routing_key"];
        m_uri = config["uri"];
        m_queue = config["queue"];
}

void RabbitMQ::producer(const char * content) {
    AmqpClient::Channel::ptr_t channel = AmqpClient::Channel::Create(m_host,m_port,m_username,m_password,m_vhost);
    AmqpClient::BasicMessage::ptr_t message = AmqpClient::BasicMessage::Create(content);
    channel->BasicPublish(m_exchange, m_routing_key, message);
}


void RabbitMQ::consumer() {
    AmqpClient::Channel::ptr_t channel = AmqpClient::Channel::CreateFromUri(m_uri);
    AmqpClient::Envelope::ptr_t envelope;
    const string &q = m_queue;
    channel->BasicConsume(q);
    while(1) {
        AmqpClient::Envelope::ptr_t envelope = channel->BasicConsumeMessage();
        if(envelope && envelope->Message()) {
            string objectName = envelope->Message()->Body();
            OSSManager oss(OSS_CONFIG_PATH);
            string bucketName = "oss-learing";
            string filePath = string("../")+objectName; 
            std::cout << "filePath :" << filePath << std::endl;
            std::cout << "objectName: "  << objectName << std::endl;
            bool ok = oss.upload_file(bucketName, objectName, filePath);
            if(!ok) {
                std::cout << "failed to upload oss" << std::endl;
            }
        }
    }
}


