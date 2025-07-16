// CloudiskServer.h
#pragma once
#include <wfrest/HttpServer.h>
#include <workflow/WFFacilities.h>

class CloudiskServer
{
public:
    CloudiskServer() {}

    void register_modules();

    int start(unsigned short port) { 
        return m_server.start(port); 
    }
    
    void stop() { m_server.stop(); }

    void list_routes() { m_server.list_routes(); }

    CloudiskServer& track()
    {
        m_server.track();
        return *this;
    }

private:
    // 路由注册模块
    void register_static_resources_module();
    void register_signup_module();
    void register_signin_module();
    void register_userinfo_module();
    void register_fileupload_module();
    void register_filelist_module();
    void register_filedownload_module();


private:
    wfrest::HttpServer m_server;
    void register_callback(const wfrest::HttpReq* req, wfrest::HttpResp *resp, SeriesWork *series);
    void login_callback(const wfrest::HttpReq* req, wfrest::HttpResp *resp, SeriesWork *series);
    void getinfo_callback(const wfrest::HttpReq* req, wfrest::HttpResp *resp, SeriesWork *series);
    void search_file_callback(const wfrest::HttpReq* req, wfrest::HttpResp *resp, SeriesWork *series);
    void upload_callback(const wfrest::HttpReq* req, wfrest::HttpResp *resp, SeriesWork *series);
    void download_callback(const wfrest::HttpReq* req, wfrest::HttpResp *resp, SeriesWork *series);
};