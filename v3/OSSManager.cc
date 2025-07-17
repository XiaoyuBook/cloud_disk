#include "OSSManager.h"
#include <iostream>

using namespace AlibabaCloud::OSS;
using json = nlohmann::json;

OSSManager::OSSManager(const char * config_path) {
    InitializeSdk();
    get_OSSManager_config(config_path);
    ClientConfiguration conf;
    m_client = std::make_unique<OssClient>(m_endpoint, m_accessKeyId, m_accessKeySecret, conf);
}

OSSManager::~OSSManager() {
    ShutdownSdk();
}

void OSSManager::get_OSSManager_config(const char* config_path) {
    using std::cout;
    using std::endl;
    cout << "config_path:" << config_path<<endl;
    std::ifstream ifs(config_path);
    if(!ifs.is_open()) {
        std::cout << "无法打开配置文件" << std::endl;
        return;
    }
    json config = json::parse(ifs);
    m_endpoint = config["endpoint"];
    m_accessKeyId = config["accessKeyId"];
    m_accessKeySecret = config["accessKeySecret"];
    cout << "endpoint:  " << m_endpoint<< endl;
    cout << "accessKeyId:  " <<m_accessKeyId<<endl;
    cout << "accessKeySecret:  " << m_accessKeySecret<<endl;
}

bool OSSManager::upload_file(const std::string& bucketName,
                             const std::string& objectName,
                             const std::string& localFilePath) {
    auto outcome = m_client->PutObject(bucketName, objectName, localFilePath);
    if (!outcome.isSuccess()) {
        std::cout << "PutObject fail, code: " << outcome.error().Code()
                  << ", message: " << outcome.error().Message()
                  << ", requestId: " << outcome.error().RequestId() << std::endl;
        return false;
    }
    return true;
}



