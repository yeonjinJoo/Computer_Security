#ifndef CLOUD_SYNC_H
#define CLOUD_SYNC_H
#include "crow_all.h"
using namespace std;

class CloudSync {
    std::string cloudDir;
    std::string tarDir;
    public:
    // eventually we'll want some parameters for the directories..
    CloudSync() : cloudDir("/tmp/cloud/"), tarDir("/tmp/tar/") { } ;

    crow::response passwordSyncUp(const string &user, const string& tarball);
    void setupUser(const string& hexuser);

};

#endif
