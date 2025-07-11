#include <iostream>
#include <workflow/WFTaskFactory.h>
#include <workflow/WFHttpServer.h>
#include <workflow/HttpUtil.h>
#include <workflow/WFFacilities.h>
#include <workflow/HttpMessage.h>
#include <workflow/MySQLResult.h>
#include <workflow/Workflow.h>
#include <signal.h>
#include <fcntl.h>
#include <string>
#include <fstream>

#include "CryptoUtil.h"

using namespace protocol;
using std::endl;
using std::cout;
using std::string;
using std::cerr;

#define PORT 9527


class Router{
    public:
    Router(){

    }
    void route(WFHttpTask *task) {
        HttpRequest *req = task->get_req();
        HttpResponse *resp = task->get_resp();

        string method = req->get_method();
        string path = req->get_request_uri();
        
        if(path == "/hello") {
            resp->append_output_body("Hello from root path!");
        }


    };

};

class Server{
    public:
    Server(int port, Router & router):m_router(router),m_port(port), m_server(std::bind(&Router::route, &router, std::placeholders::_1)){
        
    }
    int start() {
        int start_ret = m_server.start(m_port);
        return start_ret;
    }
    int stop() {
        m_server.stop();
        return 0;
    }
    private:
    // 路由
    Router &m_router;
    // 端口
    int m_port;
    // 服务器
    WFHttpServer m_server;
};


// static WFFacilities::WaitGroup global_wait_group{1};

int main(){
    Router router;
    Server server{PORT, router};
    if(!server.start()) {
        //global_wait_group.wait();
        getchar();
        server.stop();
    } else {
        cerr << "Server start failed!" << endl;
        exit(1);
    }
    return 0;
}

