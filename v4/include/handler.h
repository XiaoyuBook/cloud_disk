// handler.h
#include <iostream>
#include <workflow/WFTaskFactory.h>
#include <workflow/HttpUtil.h>
#include <workflow/WFFacilities.h>
#include <workflow/HttpMessage.h>
#include <workflow/MySQLResult.h>
#include <workflow/Workflow.h>
#include <signal.h>
#include <fcntl.h>
#include <string>
#include <fstream>
#include <wfrest/HttpServer.h>
#include <vector>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>
#include "CryptoUtil.h"
#include "nlohmann/json.hpp"
#include <alibabacloud/oss/OssClient.h>
#include <stdlib.h>
#include <stdio.h>

#include "OSSManager.h"
#include "cloud_disk_service.srpc.h"


using namespace AlibabaCloud::OSS;
using namespace wfrest;
using namespace protocol;
using json = nlohmann::json;
using std::endl;
using std::cout;
using std::string;
using std::cerr;


#define MYSQL_URL "mysql://root:123456@127.0.0.1/wd_project2"
#define PORT 9527
#define MAX_RETRY 3
#define RPC_IP "127.0.0.1"
#define RPC_PORT 1412

struct Context {
    string username;
    string password;
    HttpResp* resp;
    int id;
};



// 之前代码中的 sha256_hash 函数
inline std::string sha256_hash(const char *data) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    // 初始化、更新和完成哈希计算
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, strlen(data));
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    
    EVP_MD_CTX_free(ctx);

    // 将哈希值转换为十六进制字符串
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return ss.str();
}