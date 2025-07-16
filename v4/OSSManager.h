#ifndef OSS_MANAGER_H
#define OSS_MANAGER_H

#include <string>
#include <memory>
#include <fstream>
#include <alibabacloud/oss/OssClient.h>
#include "nlohmann/json.hpp"

class OSSManager {
public:
    explicit OSSManager(const char* config_path);
    ~OSSManager();

    bool upload_file(const std::string& bucketName,
                    const std::string& objectName,
                    const std::string& localFilePath);

private:
    void get_OSSManager_config(const char* config_path);

    std::string m_endpoint;
    std::string m_accessKeyId;
    std::string m_accessKeySecret;
    std::unique_ptr<AlibabaCloud::OSS::OssClient> m_client;
};

#endif