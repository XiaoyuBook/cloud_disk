#pragma once
#include <string>

class CryptoUtil
{
public:
    static std::string generate_salt(int length = 8);
    static std::string hash_password(std::string& password, std::string& salt);
    static std::string generate_token(const std::string& username);
    static bool verify_token(const std::string& token, std::string& username);
private:
    /* 禁止构造对象 */
    CryptoUtil() = delete;
};

