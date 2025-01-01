#include "crow_all.h"
#include "cloudsync.h"
#include "regdb.h"
#include <filesystem>
// #define CROW_STATIC_DIRECTORY ""
using namespace std;


int main()
{
    crow::SimpleApp app;
    const std::string keyfile("/var/bcpwm/confirmkey");
    const std::string tarpath("/var/bcpwm/tar/");
    const std::string rulepath("/var/bcpwm/rules");
    const std::string regpath("var/bcpwm/register_rule.html");

    CloudSync userCloud;
    RegDB regDB(keyfile);

    CROW_ROUTE(app, "/sync_up/<string>/<string>").methods(crow::HTTPMethod::POST)(
        [&](const crow::request& req,const std::string& u, const std::string& p){
            auto s = regDB.checkUserPass(u,p); 
            if (s == RegDB::RDB_SUCCESS)
                return userCloud.passwordSyncUp(u,req.body);
            if (s == RegDB::RDB_FAIL)
                return crow::response(401);
            if (s == RegDB::RDB_RECORD_NOT_FOUND)
                return crow::response(404);
            return crow::response(500);
    });

    CROW_ROUTE(app, "/sync_down/<string>")(
        [&](crow::response& res, const std::string& u_tar){
            filesystem::current_path(tarpath);
            res.set_static_file_info(u_tar);
            res.end();
    });

    CROW_ROUTE(app,"/get_rule/<string>")(
        [&](crow::response& res, const std::string& s_bcr){
            filesystem::current_path(rulepath);
            res.set_static_file_info(s_bcr);
            res.end();
    });

    CROW_ROUTE(app,"/register_rule")(
        [&](crow::response& res){
            filesystem::current_path(std::string("/"));
            res.set_static_file_info(regpath);
            res.end();
    });

    CROW_ROUTE(app, "/init_client/<string>/<string>")(
        [&](const std::string& hexmail, const std::string& hexpass) {
            switch(regDB.startRegister(hexmail,hexpass)) {
                case RegDB::RDB_SUCCESS:
                    return crow::response(200);
                case RegDB::RDB_ALREADY_EXISTS:
                    return crow::response(409);
                default:
                    return crow::response(400);
            }
    });
    
    CROW_ROUTE(app,"/confirm-client/<string>/<string>/<string>")(
        [&](const std::string& hexmail, const std::string& hexpass, const std::string& token) {
            switch(regDB.confirmRegister(hexmail,hexpass,token)) {
                case RegDB::RDB_ALREADY_EXISTS:
                    return crow::response(409);
                case RegDB::RDB_SUCCESS:
                    try {
                       userCloud.setupUser(hexmail);
                    } catch (...) { return crow::response(500); }
                    return crow::response(200); 
                default:
                    return crow::response(500);
            }
    });

    CROW_ROUTE(app,"/post-rule/init/<string>/<string>").methods(crow::HTTPMethod::POST)(
        [&](const crow::request& req, const std::string& site, const std::string& user){
            crow::multipart::message msg(req);
            const std::string file = msg.parts[0].body;
            const std::string b64file = crow::utility::base64encode(file,file.size());
            if (regDB.startRulePost(site,user,b64file) == RegDB::RDB_SUCCESS) {
                return crow::response(200);
            } else {
                return crow::response(400);
            }
    });

    CROW_ROUTE(app,"/post-rule/confirm/<string>/<string>")(
        [&](const std::string& site, const std::string& token) {
            switch(regDB.confirmRulePost(site,token)) {
                case RegDB::RDB_RECORD_NOT_FOUND:
                    return crow::response(400);
                case RegDB::RDB_SUCCESS:
                    return crow::response(200);
                default:    
                    return crow::response(500);
            }
    });
    app.ssl_file("/etc/bci/bci-cert/bcpwm.pem", "/etc/bci/bci-cert/bcpwm-key.pem")
        .port(443).multithreaded().run();
}
