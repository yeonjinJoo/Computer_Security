#ifndef REGDB_H
#define REGDB_H
#include <string>
using namespace std;

class RegDB {
    private: 
    const string keyfileName;

    public:
    RegDB(const string& keyfile) : keyfileName(keyfile) { };

    int callSiteSQL(const string& py_file, const string& user_arg, const string& pwd_arg,
        const string& token_arg, const string& file_arg);
    int callSQL(const string& py_file, const string& user_arg, const string& pwd_arg,
        const string& token_arg, const string& file_arg);
    int sendUserMail(const string& hexuser, const string& hexpass, const string& token);
    int sendSiteMail(const string& acct, const string& site, const string& token);

    enum result { RDB_SUCCESS, RDB_FAIL, RDB_ALREADY_EXISTS, RDB_RECORD_NOT_FOUND };

    result checkUserPass(const std::string& hexuser, const std::string& hexpass);
    result startRegister(const string& hexuser, const string& hexpass);
    result confirmRegister(const string& hexuser, const string& hexpass, const string& b64token);

    result startRulePost(const string& site, const string& acct, const string& file);
    result confirmRulePost(const string& site, const string& b64token);
    string genConfirmCode();
};
#endif
