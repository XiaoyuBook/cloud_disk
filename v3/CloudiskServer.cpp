// CloudiskServer.cpp
#include "CloudiskServer.h"
#include "handler.h"
#include "RabbitMQ.h"

using namespace wfrest;
using std::string;


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
            resp->String("SUCCESS");
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
                    {"data", {
                        {"Username", ctx->username},  
                        {"Token", token},           
                        {"Location", "/static/view/home.html"}
                    }}
                };
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
                string msg = "disk/"+username +"/" + filename;
                r.producer(msg.c_str());

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