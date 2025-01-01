#include "regdb.h"
#include <iostream>
#include <filesystem>
#include <time.h>
#include <sodium.h>
#include <fstream>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
using namespace std;

string dehex(const string& hex_str) {
    int len = hex_str.length();
    string dehex_str;
    for(int i=0; i< len; i+=2) {
        string byte = hex_str.substr(i,2);
        char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
        dehex_str.push_back(chr);
    }
    return dehex_str;
}

int RegDB::callSQL(const string& mode, const string& hexuser, const string& hexpass,
        const string& token_arg, const string& file_arg) {
    char cmd [4096];
    sprintf(cmd, "python3 /var/bcpwm/sql_scripts/call_regdb_SQL.py '%s' '%s' '%s' '%s' '%s'",
        mode.c_str(), dehex(hexuser).c_str(), dehex(hexpass).c_str(),
            token_arg.c_str(), file_arg.c_str());
    return system(cmd);
}

int RegDB::callSiteSQL(const string& mode, const string& site, const string& hexpass,
        const string& token_arg, const string& file_arg) {
    char cmd [4096];
    sprintf(cmd, "python3 /var/bcpwm/sql_scripts/call_regdb_SQL.py '%s' '%s' '%s' '%s' '%s'",
        mode.c_str(), site.c_str(), hexpass.c_str(),
            token_arg.c_str(), file_arg.c_str());
    return system(cmd);
}


int RegDB::sendUserMail(const string& hexuser, const string& hexpass, const string& token) {         
    string user = dehex(hexuser);
    cout << "Sending token " << token << " to " << user << endl;
    
    stringstream body;
    body << "Your registration code for bcpwm, the Badly Coded Password Manager, is: "
            << token << endl << endl
        << "You can enter this code in the application or complete the registration by visiting "
        << "http://bcpwm.badlycoded.net/confirm-client/"
            << hexuser << "/" << hexpass << "/" << token << endl;
    char cmd [500];
    sprintf(cmd, "echo '%s' | mail --config-verbose --no-config -s \"bcpwm registration confirmation\" %s",
        body.str().c_str(), user.c_str());
    return system(cmd);
}

int RegDB::sendSiteMail(const string& acct, const string& site, const string& token) {
    stringstream email;
    email << acct << "@" << site;
    cout << "Sending token " << token << " to " << email.str() << endl;

    stringstream body;
    body << "Your registration code for bcpwm, the Badly Coded Password Manager, is: "
            << token << endl << endl
        << "This code can be used to add a rules file for your site to the cloud server. "
        << "You can enter this code in the application or complete the registration by visiting "
        << "http://bcpwm.badlycoded.net/post-rule/confirm/"
            << site << "/" << token << endl;
    char cmd [500];
    sprintf(cmd, "echo '%s' | mail --config-verbose --no-config -s \"bcpwm registration confirmation\" %s",
        body.str().c_str(), email.str().c_str());
    return system(cmd);
}

RegDB::result 
RegDB::checkUserPass(const string& hexuser, const string& hexpass) {
    if (RegDB::callSQL("--check-pass", hexuser, hexpass, "", "") != 0)
        return RegDB::RDB_FAIL;
    return RegDB::RDB_SUCCESS;
}
    
RegDB::result 
RegDB::startRegister(const string& hexuser, const string& hexpass) {
    string token = this->genConfirmCode();
    if (RegDB::callSQL("--check-user", hexuser, "", "", "") != 0)
        return RegDB::RDB_ALREADY_EXISTS;
    if (RegDB::callSQL("--create-reg", hexuser, hexpass, token, "") != 0)
        return RegDB::RDB_FAIL;
    if (RegDB::sendUserMail(hexuser, hexpass, token) != 0)
        return RegDB::RDB_FAIL;
    return RegDB::RDB_SUCCESS;
}

RegDB::result 
RegDB::confirmRegister(const string& hexuser, const string& hexpass, const string& b64token) {
    if (RegDB::callSQL("--check-user", hexuser, "", "", "") != 0)
        return RegDB::RDB_ALREADY_EXISTS;
    if (RegDB::callSQL("--check-token", hexuser, hexpass, b64token, "") != 0)
        return RegDB::RDB_FAIL;
    if (RegDB::callSQL("--delete-reg", hexuser, hexpass, b64token, "") != 0)
        return RegDB::RDB_FAIL;
    if (RegDB::callSQL("--create-user", hexuser, hexpass, "", "") != 0)
        return RegDB::RDB_FAIL;
    return RegDB::RDB_SUCCESS;
}

const char *hexlify[] = {
  "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B", "0C", "0D", "0E", "0F", 
  "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1A", "1B", "1C", "1D", "1E", "1F", 
  "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2A", "2B", "2C", "2D", "2E", "2F", 
  "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3A", "3B", "3C", "3D", "3E", "3F", 
  "40", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4C", "4D", "4E", "4F", 
  "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5A", "5B", "5C", "5D", "5E", "5F", 
  "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6A", "6B", "6C", "6D", "6E", "6F", 
  "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7A", "7B", "7C", "7D", "7E", "7F", 
  "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A", "8B", "8C", "8D", "8E", "8F", 
  "90", "91", "92", "93", "94", "95", "96", "97", "98", "99", "9A", "9B", "9C", "9D", "9E", "9F", 
  "A0", "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "AA", "AB", "AC", "AD", "AE", "AF", 
  "B0", "B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9", "BA", "BB", "BC", "BD", "BE", "BF", 
  "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB", "CC", "CD", "CE", "CF", 
  "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9", "DA", "DB", "DC", "DD", "DE", "DF", 
  "E0", "E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "EA", "EB", "EC", "ED", "EE", "EF", 
  "F0", "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "FA", "FB", "FC", "FD", "FE", "FF"  
};


void get_pwr_sitehash(const std::string& site, std::string &sh_out) {
    unsigned char sitehash[crypto_hash_BYTES] = {0};
    unsigned char usite[256] = {0};
    long slen = site.length();
    for (int i = 0; i < slen; i++) usite[i] = (unsigned char)site[i];
    sh_out.clear();
    crypto_hash(sitehash,usite,slen);
    for(int i = 0; i < 16; i++) sh_out.append(hexlify[sitehash[i]]);
    cerr << "sh_out is " << sh_out << endl;
}


RegDB::result 
RegDB::startRulePost(const string& site, const string& acct, const string& file) {
    string token = this->genConfirmCode();
    std::string sitehash;
    get_pwr_sitehash(site, sitehash);
    cerr << "sitehash is" << sitehash << endl;
    cerr << "file is" << file << endl;
    if (RegDB::callSiteSQL("--create-site-reg", sitehash, "", token, file) != 0)
        return RegDB::RDB_FAIL;
    if (RegDB::sendSiteMail(acct, site, token) != 0)
        return RegDB::RDB_FAIL;
    return RegDB::RDB_SUCCESS;
}

RegDB::result 
RegDB::confirmRulePost(const string& site, const string& b64token) {
    std::string sitehash;
    get_pwr_sitehash(site,sitehash);
    if (RegDB::callSiteSQL("--check-site-token", sitehash, "", b64token, "") != 0)
        return RegDB::RDB_RECORD_NOT_FOUND;
    char cmd [1000];
    sprintf(cmd, "python3 /var/bcpwm/sql_scripts/write_rule_file.py '%s' '%s'",
        sitehash.c_str(), b64token.c_str());
    if (system(cmd) != 0)
        return RegDB::RDB_FAIL;
    return RegDB::RDB_SUCCESS;
}

string RegDB::genConfirmCode() {
    int hashfd = -1;
    std::ifstream keyfile(this->keyfileName);
    char hashinput[32+sizeof(time_t)];
    keyfile.read(hashinput,32);
    keyfile.close();
    string hashfileName = this->keyfileName + ".tohash";
    time_t now = time(nullptr);
    char *cnow = (char *) &now;
    for(int i = 0; i < sizeof(time_t); i++) hashinput[32+i] = cnow[i];    
    do {
        hashfd = open(hashfileName.c_str(),O_CREAT | O_WRONLY | O_EXCL);
    } while (hashfd <= 0);
    // file locked, write the hashinput
    write(hashfd,hashinput,32+sizeof(time_t));
    close(hashfd);
    char cmd[1024];
    sprintf(cmd, 
    "python3 -c 'import base64, hashlib; print(base64.b64encode(hashlib.file_digest(open(\"%s\",\"rb\"),\"sha3_224\").digest())[:12].decode(\"utf-8\"))'",
    hashfileName.c_str());
    FILE *hashoutF = popen(cmd, "r");
    char code[13];
    string codeout = string(fgets(code, 13, hashoutF));
    pclose(hashoutF);
    unlink(hashfileName.c_str());
    return codeout;
}
