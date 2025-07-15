#include "OSSManager.h"
#include <iostream>

using namespace AlibabaCloud::OSS;

OSSManager::OSSManager(const std::string& endpoint,
                       const std::string& accessKeyId,
                       const std::string& accessKeySecret,
                       const ClientConfiguration& conf)
{
    InitializeSdk();
    client_ = std::make_unique<OssClient>(endpoint, accessKeyId, accessKeySecret, conf);
}

OSSManager::~OSSManager() {
    ShutdownSdk();
}

bool OSSManager::upload_file(const std::string& bucketName,
                             const std::string& objectName,
                             const std::string& localFilePath) {
    auto outcome = client_->PutObject(bucketName, objectName, localFilePath);
    if (!outcome.isSuccess()) {
        std::cout << "PutObject fail, code: " << outcome.error().Code()
                  << ", message: " << outcome.error().Message()
                  << ", requestId: " << outcome.error().RequestId() << std::endl;
        return false;
    }
    return true;
}
