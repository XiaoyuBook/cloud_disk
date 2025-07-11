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
class MyRouter {
public:
    MyRouter(HttpServer &server) : m_server(server) {
        // 注册
        m_server.POST("/user/signup", [](const HttpReq *req, HttpResp *resp) {
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

            WFMySQLTask *sql_task = WFTaskFactory::create_mysql_task(MYSQL_URL, MAX_RETRY, [resp](WFMySQLTask * sql_task) { 
                if (sql_task->get_state() != WFT_STATE_SUCCESS) {
                    resp->set_status_code("500 Internal Server Error");
                    resp->append_output_body_nocopy("<html>500 Internal Server Error</html>");
                    return ;
                }
            
                if (sql_task->get_resp()->get_packet_type() == MYSQL_PACKET_ERROR) {            
                    resp->set_status_code("400 Bad Request");
                    resp->append_output_body_nocopy("<html>用户名已存在</html>");
                    return ;
                }
               resp->append_output_body_nocopy("恭喜您，注册成功！");   
            });
            string sql = "INSERT INTO tbl_user (username, password, salt) VALUES (\"" +
            username + "\", \"" +
            hashcode + "\", \"" +
            salt + "\")";
            cout << "[SQL]" << sql << endl;
            sql_task->get_req()->set_query(sql);
            sql_task->start();
       
        });







    }
   

private:
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
        getchar();
        cout << "exit!" <<endl;
        server.stop();
    } else {
        cerr << "Server start failed!" << endl;
        exit(1);
    }
    
    return 0;
}