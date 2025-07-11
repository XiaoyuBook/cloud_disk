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

using namespace protocol;
using std::endl;
using std::cout;
using std::string;
using std::cerr;
using namespace wfrest;
#define PORT 9527

class MyRouter {
public:
    MyRouter(HttpServer &server) : m_server(server) {
        m_server.GET("/hello", [](const HttpReq *req, HttpResp *resp) {
            resp->String("hello world!");
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