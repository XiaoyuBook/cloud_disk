#include "../include/CryptoUtil.h"
#include "../include/cloud_disk_service.srpc.h"
#include "../include/handler.h"
#include <alibabacloud/oss/http/HttpType.h>
#include <wfrest/HttpServer.h>
#include <workflow/MySQLResult.h>
#include <workflow/WFTask.h>
#include <workflow/WFTaskFactory.h>
#include <chrono>
#include "ppconsul/agent.h"


using namespace srpc;
using ppconsul::Consul;
using namespace ppconsul::agent;
using std::string;

#define CONSUL_IP "127.0.0.1"
#define CONSUL_PORT 8500
#define RPC_IP "127.0.0.1"

// RPC服务启动，向consul注册，consul获取到rpc实例的信息
Consul consul { "http://127.0.0.1:8500", ppconsul::kw::dc="dc1" };
// 创建代理
Agent agent { consul };


static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signo)
{
	wait_group.done();
}

class cloud_disk_serviceServiceImpl : public cloud_disk_service::Service
{
public:
	void signup(signup_request *request, signup_response *response, srpc::RPCContext *ctx) override {
		string username = request->username();
        string password = request->password();
        string salt = CryptoUtil::generate_salt();
        string hashcode = CryptoUtil::hash_password(password,salt);
        WFMySQLTask* sql_task = WFTaskFactory::create_mysql_task(
            MYSQL_URL, MAX_RETRY, [response](WFMySQLTask *task) {
                if(task->get_state() != WFT_STATE_SUCCESS) {
					response->set_state_code(500);
                    response->set_message("task or network error!");
                    return;
                }
                if(task->get_resp()->get_packet_type() == MYSQL_PACKET_ERROR) {
					string errmsg = task->get_resp()->get_error_msg();
					int errcode = task->get_resp()->get_error_code();
					std::cerr << "MySQL Error [" << errcode << "]: " << errmsg << std::endl;
				
					response->set_state_code(400);
					response->set_message(std::string("MySQL error: ") + errmsg);
					return;
                }
				response->set_state_code(201);
                response->set_message("SUCCESS");
            });
            string sql = "INSERT INTO tbl_user (username, password, salt) VALUES (\"" +
            username + "\", \"" +
            hashcode + "\", \"" +
            salt + "\")";
            sql_task->get_req()->set_query(sql);
            ctx->get_series()->push_back(sql_task);
	}

	void signin(signin_request *request, signin_response *response, srpc::RPCContext *ctx) override {
		string username = request->username();
		string password = request->password();
		string salt = CryptoUtil::generate_salt();
        string hashcode = CryptoUtil::hash_password(password,salt);
		

		string sql = "SELECT * FROM tbl_user WHERE username ='" + username +"'";
		WFMySQLTask *sql_task = WFTaskFactory::create_mysql_task(MYSQL_URL, MAX_RETRY,
		[response, username, password](WFMySQLTask* sql_task1) {
			if(sql_task1->get_state() != WFT_STATE_SUCCESS) {
				response->set_state_code(500);
				return;
			}
			
			MySQLResultCursor cursor {sql_task1->get_resp()};
			std::vector<MySQLCell> record;
			bool success = cursor.fetch_row(record);
			if(!success) {
				response->set_state_code(401);
				return;
			}

			string db_hashcode = record[2].as_string();
			string db_salt = record[3].as_string();
			string temp = password;
			string gen_hashcode = CryptoUtil::hash_password(temp,db_salt);
			if(gen_hashcode == db_hashcode) {
				response->set_state_code(200);
				string token = CryptoUtil::generate_token(username);
				response->set_username(username);
				response->set_token(token);
				response->set_location("/static/view/home.html");
			} else {
				response->set_state_code(400);
			}
		});
	sql_task->get_req()->set_query(sql);
	ctx->get_series()->push_back(sql_task);
	}
};


void timer_callback(WFTimerTask* task)
{
    // 发送心跳包
    agent.servicePass("user_service1");

    WFTimerTask* next = WFTaskFactory::create_timer_task(9, 0, timer_callback);
    series_of(task)->push_back(next);
}

int main()
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	SRPCServer server;
	cloud_disk_serviceServiceImpl cloud_disk_service_impl;
	server.add_service(&cloud_disk_service_impl);

	server.start(RPC_PORT);
	// 这里加入consul
	HttpServer http_server;
	if(http_server.start(8888) == 0) {
		agent.registerService(
			kw::id = "user_service1",
            kw::name = "user_service",
            kw::address = RPC_IP,
            kw::port = RPC_PORT,
            kw::check = TtlCheck(std::chrono::seconds{ 10 })
		);
		agent.servicePass("user_service1");
		WFTimerTask* task = WFTaskFactory::create_timer_task(9, 0, timer_callback);
        task->start();
	} else {
        std::cerr << "Error: cannot start server!\n";
        std::exit(1);
    }
	// 这里结束新增部分
	wait_group.wait();
	server.stop();
	http_server.stop();
	google::protobuf::ShutdownProtobufLibrary();
	return 0;
}
