#ifndef OSS_MANAGER_H
#define OSS_MANAGER_H

#include <string>
#include <memory>
#include <alibabacloud/oss/OssClient.h>

class OSSManager {
public:
    OSSManager(const std::string& endpoint,
               const std::string& accessKeyId,
               const std::string& accessKeySecret,
               const AlibabaCloud::OSS::ClientConfiguration& conf);

    ~OSSManager();

    bool upload_file(const std::string& bucketName,
                     const std::string& objectName,
                     const std::string& localFilePath);

private:
    std::unique_ptr<AlibabaCloud::OSS::OssClient> client_;
};

#endif
