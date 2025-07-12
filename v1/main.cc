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
struct user {
    string username;
    string password;
    string hashcode;
    string salt;
};


struct Context {
    string username;
    string password;
    HttpResp* resp;
    int id;
};






std::string sha256_hash(const char *data) {
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

static WFFacilities::WaitGroup global_wait_group{1};

class MyRouter {
public:
    MyRouter(HttpServer &server) : m_server(server) {
        // 注册
        m_server.POST("/user/signup", [this](const HttpReq *req, HttpResp *resp,SeriesWork *series){
            this->register_callback(req, resp,series);
        });

        // 登录
        m_server.POST("/user/signin",[this](const HttpReq *req, HttpResp *resp, SeriesWork *series){
            this->login_callback(req,resp,series);
        });

        // 获取用户信息
        m_server.GET("/user/info",[this](const HttpReq* req, HttpResp *resp,SeriesWork *series){
            this->getinfo_callback(req,resp,series);
        });

        // 文件列表查询
        m_server.POST("/file/query",[this](const HttpReq* req,HttpResp *resp,SeriesWork* series) {
            this->search_file_callback(req, resp, series);
        });

        // 文件上传
        m_server.POST("/file/upload",[this](const HttpReq* req,HttpResp *resp,SeriesWork* series) {
            this->upload_callback(req, resp, series);
        });
        // 文件下载
        m_server.GET("/file/download",[this](const HttpReq* req,HttpResp *resp,SeriesWork* series) {
            this->download_callback(req, resp, series);
        });
    }

private:
void print_userdata() {
    // username,token;
}
// 注册函数实现
void register_callback(const HttpReq* req, HttpResp *resp, SeriesWork *series) {
    auto & form = req->form_kv();
    auto username_it = form.find("username");
    auto password_it = form.find("password");
    if (username_it == form.end() || password_it == form.end()) {
        resp->set_status(400);
        resp->String("Missing username or password");
        return;
    }
    string username = username_it->second;
    string password = password_it->second;
    string salt = CryptoUtil::generate_salt();
    string hashcode = CryptoUtil::hash_password(password, salt);

    
    WFMySQLTask* sql_task = WFTaskFactory::create_mysql_task(
        MYSQL_URL,
        MAX_RETRY,
        [resp](WFMySQLTask* task) {
            if (task->get_state() != WFT_STATE_SUCCESS) {
                resp->set_status(500);
                resp->String("Task or network error");
               return;
            }
            if(task->get_resp()->get_packet_type() == MYSQL_PACKET_ERROR){
                resp->set_status_code("400 Bad Request");
                resp->append_output_body_nocopy("<html>用户名已存在</html>");
                return;
            }
            resp->set_status(201); 
            resp->String("Registration successful");
        }
    );
    string sql = "INSERT INTO tbl_user (username, password, salt) VALUES (\"" +
    username + "\", \"" +
    hashcode + "\", \"" +
    salt + "\")";
    cout << "[SQL]" << sql << endl;
    sql_task->get_req()->set_query(sql);
    series->push_back(sql_task);
   }

// 登录函数实现

void login_callback(const HttpReq* req, HttpResp *resp,SeriesWork *series){
    auto & form = req->form_kv();
    auto username_it = form.find("username");
    auto password_it = form.find("password");
    if (username_it == form.end() || password_it == form.end()) {
        resp->set_status(400);
        resp->String("Missing username or password");
        return;
    }


    string username = username_it->second;
    string password = password_it->second;
    auto ctx = new Context{username, password, resp};   


    string sql = "SELECT * FROM tbl_user WHERE username='" + username + "'";
    cout << "[SQL] " << sql << "\n";
    WFMySQLTask* sql_task = WFTaskFactory::create_mysql_task(MYSQL_URL, MAX_RETRY,
        [ctx](WFMySQLTask *sql_task){
            auto resp = ctx->resp;
            if(sql_task->get_state() != WFT_STATE_SUCCESS) {
                resp->set_status(500);
                resp->String("Database error");
                delete ctx;
                return;
            }
            MySQLResultCursor cursor{sql_task->get_resp()};
            std::vector<MySQLCell> record;
            bool success = cursor.fetch_row(record);
            if (!success) {
                resp->set_status(401);
                resp->String("Invalid username or password");
                delete ctx;
                return;
            }
            
            
            string db_hashcode = record[2].as_string(); 
            string db_salt = record[3].as_string();
            string temp = ctx->password;     
            string gen_hashcode = CryptoUtil::hash_password(temp, db_salt);
            if (gen_hashcode == db_hashcode) {
                resp->set_status(200);
                string token = CryptoUtil::generate_token(ctx->username);
                json ret = {
                    "data", {
                        {"username",ctx->username},
                        {"Location","/static/view/home.html"},
                        {"token",token}
                    }
                };

                resp->String("welcome to cloud_disk\n");
                resp->String(ret.dump(2));

            } else {
                resp->set_status(401);
                resp->String("Invalid username or password");
            }
            delete ctx;
        }
    );
    sql_task->get_req()->set_query(sql);
    series->push_back(sql_task);

}

// 获取用户信息
void getinfo_callback(const HttpReq *req, HttpResp *resp, SeriesWork *series) {
    string  username = req->query("username");
    const string & token = req->query("token");
    if(!CryptoUtil::verify_token(token, username)){
        resp->set_status_code("401"); 
        resp->append_output_body_nocopy("<html>401 Unauthorized</html>");
        return ;
    } 
    string sql = "SELECT * FROM tbl_user WHERE username = '" + username +"'";
    cout << "[SQL]" << sql << endl;
    WFMySQLTask *sql_task = WFTaskFactory::create_mysql_task(MYSQL_URL,MAX_RETRY,[resp](WFMySQLTask *sql_task){
        if(sql_task->get_state() != WFT_STATE_SUCCESS ) {
            resp->set_status(500);
            resp->String("Database error!");
            return;
        }
        MySQLResultCursor cursor {sql_task->get_resp()};
        std::vector<MySQLCell> record;
        bool success = cursor.fetch_row(record);
        if(!success) {
            resp->set_status(401);
            resp->String("Invalid username");
            return;
        }
        resp->set_status(200);
        string db_register_time = record[4].as_datetime();
        json user_info = {
            {"data", {
                {"username", record[1].as_string()},
                {"SignupAt", db_register_time}
            }}
        };
        resp->String(user_info.dump(2));
    });
    sql_task->get_req()->set_query(sql);
    series->push_back(sql_task);

}



// 获取文件列表
void search_file_callback(const HttpReq* req, HttpResp *resp,SeriesWork *series) {
    string  username = req->query("username");
    const string & token = req->query("token");
    if(!CryptoUtil::verify_token(token, username)){
        resp->set_status_code("401"); 
        resp->append_output_body_nocopy("<html>401 Unauthorized</html>");
        return ;
    }
    cout << "token is currect" << endl;

    // 先获取id，通过id查询uid
    string sql = "SELECT * FROM tbl_user WHERE username = '" + username +"'";
    WFMySQLTask *sql_task = WFTaskFactory::create_mysql_task(MYSQL_URL,MAX_RETRY,[resp,series](WFMySQLTask *sql_task){
        if(sql_task->get_state() != WFT_STATE_SUCCESS ) {
            resp->set_status(500);
            resp->String("Database error!");
            return;
        }
        MySQLResultCursor cursor {sql_task->get_resp()};
        std::vector<MySQLCell> record;
        bool success = cursor.fetch_row(record);
        if(!success) {
            resp->set_status(401);
            resp->String("Invalid username");
            return;
        }
        int uid = record[0].as_int();


           // 查询file表
        string sql2 = "SELECT * FROM tbl_file WHERE uid = " + std::to_string(uid);
        WFMySQLTask *sql_task2 = WFTaskFactory::create_mysql_task(MYSQL_URL,MAX_RETRY,[resp](WFMySQLTask *sql_task){
        if(sql_task->get_state() != WFT_STATE_SUCCESS ) {
            resp->set_status(500);
            resp->String("Database error!");
            return;
        }
        MySQLResultCursor cursor {sql_task->get_resp()};
        std::vector<MySQLCell> record;
        json result = json::array();
        while (true) {
            std::vector<MySQLCell> record;
            if (!cursor.fetch_row(record)) break;

            if (record.size() >= 8 && record[7].as_int() == 0) {
                json file_info = {
                    {"Filename",record[2].as_string()},
                    {"FileHash",record[3].as_string()},
                    {"FileSize",record[4].as_int()},
                    {"UploadAt",record[5].as_datetime()},
                    {"LastUpdated",record[6].as_datetime()}
                };
                result.push_back(file_info);
            }
        }
        if(result.empty()) {
            resp->set_status(404);
            resp->String("404 NOT FOUND");
        } else {
            resp->set_status(200);
            resp->append_output_body(result.dump(2));
        }
    });
    sql_task2->get_req()->set_query(sql2);
    series->push_back(sql_task2);

    });
    sql_task->get_req()->set_query(sql);
    series->push_back(sql_task);
}

// 上传文件
void upload_callback(const HttpReq *req, HttpResp* resp, SeriesWork *series) {
    string username = req->query("username");
    const string & token = req->query("token");

    if (!CryptoUtil::verify_token(token, username)) {
        resp->set_status_code("401"); 
        resp->append_output_body_nocopy("<html>401 Unauthorized</html>");
        return;
    }

    if (req->content_type() != MULTIPART_FORM_DATA) {
        resp->set_status(HttpStatusBadRequest);     
        return;
    }

    // 查询用户 UID
    string sql_user = "SELECT * FROM tbl_user WHERE username = '" + username + "'";
    WFMySQLTask *sql_task = WFTaskFactory::create_mysql_task(MYSQL_URL, MAX_RETRY,
        [req, resp, series,username](WFMySQLTask *sql_task) {
            if (sql_task->get_state() != WFT_STATE_SUCCESS) {
                resp->set_status(500);
                resp->String("Database error!");
                return;
            }

            MySQLResultCursor cursor{sql_task->get_resp()};
            std::vector<MySQLCell> record;
            if (!cursor.fetch_row(record)) {
                resp->set_status(401);
                resp->String("Invalid username");
                return;
            }

            int uid = record[0].as_int();
            const Form& form = req->form();

            for (const auto& [_, file] : form) {
                
                const auto& [filename, content] = file;
                string hashcode = sha256_hash(content.c_str());
                int filesize = content.size();
                string dir_path = "./disk/" + username;
                string save_path = dir_path + "/" + hashcode;
                struct stat st;
                if (stat("./disk", &st) != 0) {
                    mkdir("./disk", 0755);
                }
                
                if (stat(dir_path.c_str(), &st) != 0) {
                    mkdir(dir_path.c_str(), 0755);
                }
                resp->Save(save_path, content);
                std::string sql_insert = "INSERT INTO tbl_file(uid, filename, hashcode, size) VALUES (" +
                                         std::to_string(uid) + ", '" +
                                         filename + "', '" +
                                         hashcode + "', " +
                                         std::to_string(filesize) + ")";

                WFMySQLTask* insert_task = WFTaskFactory::create_mysql_task(MYSQL_URL, MAX_RETRY,
                    [filename, resp](WFMySQLTask* task) {
                        if (task->get_state() != WFT_STATE_SUCCESS) {
                            resp->set_status(500);
                            resp->String("Database error!");
                            return;
                        }
                        resp->set_status(200);
                        resp->String("Save " + string(filename) + " success!\n");
                    });

                insert_task->get_req()->set_query(sql_insert);
                series->push_back(insert_task);
            }
        });

    sql_task->get_req()->set_query(sql_user);
    series->push_back(sql_task);
}




void download_callback(const HttpReq *req, HttpResp *resp, SeriesWork *series) {
    std::string username = req->query("username");
    const std::string &token = req->query("token");
    std::string hashcode = req->query("hashcode");
    std::string filename = req->query("filename");

    if (!CryptoUtil::verify_token(token, username)) {
        resp->set_status_code("401"); 
        resp->append_output_body_nocopy("<html>401 Unauthorized</html>");
        return;
    }

    std::string sql_user = "SELECT * FROM tbl_user WHERE username = '" + username + "'";
    WFMySQLTask *sql_task = WFTaskFactory::create_mysql_task(MYSQL_URL, MAX_RETRY,
        [req, resp, series, hashcode, filename,username](WFMySQLTask *sql_task) {
            if (sql_task->get_state() != WFT_STATE_SUCCESS) {
                resp->set_status(500);
                resp->String("Database error!");
                return;
            }

            MySQLResultCursor cursor{sql_task->get_resp()};
            std::vector<MySQLCell> record;
            if (!cursor.fetch_row(record)) {
                resp->set_status(401);
                resp->String("Invalid username");
                return;
            }
            if(record[2].as_string() != filename) {
                resp->set_status(400);
                resp->String("Filename mismatch");
                return;
            }
            int uid = record[0].as_int();
            std::string sql2 = "SELECT * FROM tbl_file WHERE uid = " + std::to_string(uid) +
                               " AND hashcode = '" + hashcode + "'";

            WFMySQLTask* select_task = WFTaskFactory::create_mysql_task(MYSQL_URL, MAX_RETRY,
                [resp, filename,username,hashcode](WFMySQLTask* task) {
                    if (task->get_state() != WFT_STATE_SUCCESS) {
                        resp->set_status(500);
                        resp->String("Database error!");
                        return;
                    }

                    MySQLResultCursor cursor{task->get_resp()};
                    std::vector<MySQLCell> record;
                    if (!cursor.fetch_row(record)) {
                        resp->set_status(404);
                        resp->String("File not found");
                        return;
                    }
                    // 构造保存路径
                    string filepath = "./disk/" + username + "/" + hashcode;
                    struct stat st;
                    if (stat(filepath.c_str(), &st) != 0) {
                        resp->set_status(404);
                        resp->String("File missing on server");
                        return;
                    }
                    resp->set_status(200);
                    resp->File(filepath);               
                });

            select_task->get_req()->set_query(sql2);
            series->push_back(select_task);
        });

    sql_task->get_req()->set_query(sql_user);
    series->push_back(sql_task);
}

    HttpServer& m_server;
};

class Server {
public:
    Server(int port) : m_port(port), m_server(), m_router(m_server) {}

    int start() {
        int start_ret = m_server.start(m_port);
        return start_ret;
    }

    int stop() {
        m_server.stop();
        return 0;
    }

private:
    int m_port;
    HttpServer m_server;
    MyRouter m_router;
};

int main() {
    Server server(PORT);
    
    if (!server.start()) {
        // g_waitGroup.wait();
        getchar();
        cout << "exit!" <<endl;
        server.stop();
    } else {
        cerr << "Server start failed!" << endl;
        exit(1);
    }
    
    return 0;
}