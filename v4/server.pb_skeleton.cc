#include "cloud_disk_service.srpc.h"
#include "workflow/WFFacilities.h"
#include "handler.h"
using namespace srpc;

static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signo)
{
	wait_group.done();
}

class cloud_disk_serviceServiceImpl : public cloud_disk_service::Service {
public:

	void signup(signup_request *request, signup_response *response, srpc::RPCContext *ctx) override {
		string username = request->username();
        string password = request->password();
		cout << "server recieve username :" << username <<endl;
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
};

int main()
{
	GOOGLE_PROTOBUF_VERIFY_VERSION;
	unsigned short port = 1412;
	SRPCServer server;

	cloud_disk_serviceServiceImpl cloud_disk_service_impl;
	server.add_service(&cloud_disk_service_impl);

	server.start(port);
	wait_group.wait();
	server.stop();
	google::protobuf::ShutdownProtobufLibrary();
	return 0;
}
