// CloudiskServer.cpp
#include "CloudiskServer.h"
#include "handler.h"
#include "RabbitMQ.h"
#include <openssl/asn1.h>
#include <workflow/WFFacilities.h>

using namespace wfrest;
using std::string;



// rpc客户端创建
std::unique_ptr<cloud_disk_service::SRPCClient> get_srpc_client() {
    const char* ip = "127.0.0.1";
    unsigned short port = 1412;
    return std::make_unique<cloud_disk_service::SRPCClient>(ip, port);
}

void CloudiskServer::register_modules() {
    // 1.设置静态资源的路由
    register_static_resources_module();

    // 2. 注册用户相关业务API
    register_signup_module();
    register_signin_module();
    register_userinfo_module();
    
    // 3. 注册文件相关业务API
    register_filelist_module();
    register_fileupload_module();
    register_filedownload_module();
}

void CloudiskServer::register_static_resources_module()
{
    m_server.GET("/user/signup", [](const HttpReq *, HttpResp * resp){
        resp->File("static/view/signup.html");
    });

    m_server.GET("/static/view/signin.html", [](const HttpReq *, HttpResp * resp){
        resp->File("static/view/signin.html");
    });

    m_server.GET("/static/view/home.html", [](const HttpReq *, HttpResp * resp){
        resp->File("static/view/home.html");
    });

    m_server.GET("/static/js/auth.js", [](const HttpReq *, HttpResp * resp){
        resp->File("static/js/auth.js");
    });

    m_server.GET("/static/img/avatar.jpeg", [](const HttpReq *, HttpResp * resp){
        resp->File("static/img/avatar.jpeg");
    });

    m_server.GET("/file/upload", [](const HttpReq *, HttpResp * resp){
        resp->File("static/view/index.html");
    });

    m_server.Static("/file/upload_files","static/view/upload_files");
}


// 业务逻辑的实现
void CloudiskServer::register_signup_module()
{
    m_server.POST("/user/signup", [this](const HttpReq* req, HttpResp *resp, SeriesWork *series){
        this->register_callback(req,resp,series);
    });
}

void CloudiskServer::register_signin_module()
{
    m_server.POST("/user/signin", [this](const HttpReq* req, HttpResp *resp, SeriesWork *series){
        this->login_callback(req,resp,series);
    });
}

void CloudiskServer::register_userinfo_module()
{
    m_server.GET("/user/info", [this](const HttpReq* req, HttpResp *resp, SeriesWork *series){
        this->getinfo_callback(req,resp,series);
    });
}

void CloudiskServer::register_filelist_module()
{
    m_server.POST("/file/query", [this](const HttpReq* req, HttpResp *resp, SeriesWork *series){
        this->search_file_callback(req, resp, series);
    });
}

void CloudiskServer::register_fileupload_module()
{
    m_server.POST("/file/upload", [this](const HttpReq* req, HttpResp *resp, SeriesWork *series){
        this->upload_callback(req,resp,series);
    });
}

void CloudiskServer::register_filedownload_module()
{
    m_server.GET("/file/download", [this](const HttpReq* req, HttpResp *resp, SeriesWork *series){
        this->download_callback(req, resp,series);
    });
}


static void signup_done(signup_response *response, srpc::RPCContext *context){
	if(context->success()) {
		
	}
}

// 注册函数实现
void CloudiskServer::register_callback(const HttpReq* req, HttpResp *resp, SeriesWork *series) {
    auto & form = req->form_kv();
    auto username_it = form.find("username");
    auto password_it = form.find("password");
    if (username_it == form.end() || password_it == form.end()) {
        resp->set_status(400);
        resp->String("Missing username or password");
        return;
    }

    // 微服务部分
    using namespace srpc;
    GOOGLE_PROTOBUF_VERIFY_VERSION;
	cloud_disk_service::SRPCClient client(RPC_IP, RPC_PORT);

	signup_request signup_req;
    signup_req.set_username(username_it->second);
    signup_req.set_password(password_it->second);
    WFFacilities::WaitGroup wait_http { 1 };
	client.signup(&signup_req, [resp,&wait_http](signup_response *response, RPCContext *ctx){
        if(ctx->success()) {
            int code = response->state_code();
            string str = response->message();
            resp->set_status(code);
            resp->String(str);
        }
        wait_http.done();
    });
    wait_http.wait();

   }

// 登录函数实现

void CloudiskServer::login_callback(const HttpReq* req, HttpResp *resp,SeriesWork *series){
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

    // 微服务部分
    using namespace srpc;
    GOOGLE_PROTOBUF_VERIFY_VERSION;
	cloud_disk_service::SRPCClient client(RPC_IP, RPC_PORT);

	signin_request signin_req;
    signin_req.set_username(username);
    signin_req.set_password(password);
    WFFacilities::WaitGroup wait_http {1};
    client.signin(&signin_req,[resp,&wait_http](signin_response *response, RPCContext *ctx){
        if(ctx->success()){
            int code = response->state_code();
            string Username = response->username();
            string Token = response->token();
            string Location = response->location();

            json ret = {
                {"data", {
                    {"Username", Username},  
                    {"Token", Token},           
                    {"Location", Location}
                }}
            };
            resp->String(ret.dump(2));
        } else {
            resp->set_status(response->state_code());
            resp->String("Invalid username or password");
        }   
        wait_http.done();     
    });
    wait_http.wait();

}

// 获取用户信息
void CloudiskServer::getinfo_callback(const HttpReq *req, HttpResp *resp, SeriesWork *series) {
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
                {"Username", record[1].as_string()},
                {"SignupAt", db_register_time}
            }}
        };
        resp->String(user_info.dump(2));
    });
    sql_task->get_req()->set_query(sql);
    series->push_back(sql_task);

}



// 获取文件列表
void CloudiskServer::search_file_callback(const HttpReq* req, HttpResp *resp,SeriesWork *series) {
    string  username = req->query("username");
    const string & token = req->query("token");
    if(!CryptoUtil::verify_token(token, username)){
        resp->set_status_code("401"); 
        resp->append_output_body_nocopy("<html>401 Unauthorized</html>");
        return ;
    }
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
                    {"FileHash", record[3].as_string()},
                    {"FileName", record[2].as_string()}, 
                    {"FileSize", record[4].as_int()},
                    {"UploadAt", record[5].as_datetime()},
                    {"LastUpdated", record[6].as_datetime()}
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
void CloudiskServer::upload_callback(const HttpReq *req, HttpResp* resp, SeriesWork *series) {
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


                // 以下是v1版本的一个上传       
                string dir_path = "./disk/" + username;
                string save_path = dir_path + "/" + filename;
                struct stat st;
                if (stat("./disk", &st) != 0) {
                    mkdir("./disk", 0755);
                }
                
                if (stat(dir_path.c_str(), &st) != 0) {
                    mkdir(dir_path.c_str(), 0755);
                }
                resp->Save(save_path, content);

                // v3的上传
                RabbitMQ r("RabbitMQ_config.json");
                r.producer(save_path.c_str());

                std::string sql_insert = "INSERT INTO tbl_file(uid, filename, hashcode, size) VALUES (" +
                                         std::to_string(uid) + ", '" +
                                         filename + "', '" +
                                         hashcode + "', " +
                                         std::to_string(filesize) + ")";

                WFMySQLTask* insert_task = WFTaskFactory::create_mysql_task(MYSQL_URL, MAX_RETRY,
                    [resp](WFMySQLTask* task) {
                        if (task->get_state() != WFT_STATE_SUCCESS) {
                            resp->set_status(500);
                            resp->String("Database error!");
                            return;
                        }
                        resp->Redirect("/static/view/home.html", HttpStatusSeeOther);
                    });

                insert_task->get_req()->set_query(sql_insert);
                series->push_back(insert_task);
            }
        });

    sql_task->get_req()->set_query(sql_user);
    series->push_back(sql_task);
}




void CloudiskServer::download_callback(const HttpReq *req, HttpResp *resp, SeriesWork *series) {
    std::string username = req->query("username");
    const std::string &token = req->query("token");
    std::string hashcode = req->query("filehash");
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
                    string filepath = "/disk/" + username + "/" + filename;
                    if (username.empty() || filename.empty()) {
                        resp->set_status(400);
                        resp->String("Invalid filename or username");
                        return;
                    }

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
