#include "cloudsync.h"
#include "crow_all.h"
#include <filesystem>
#include <fstream>
#include <iostream>

crow::response 
CloudSync::passwordSyncUp(const string &user, const string& tarball) 
{
    using namespace std;     
    // check the user's directory exists...
    filesystem::path userDir(cloudDir + user);
    if (!filesystem::exists(userDir)) {
        return crow::response(404);
    }

    // try writing the tarball into the user's directory
    filesystem::current_path(userDir);
    string tarName = user + ".tar";
    try {
        fstream tarFile(tarName, ios::out | ios::binary | ios::trunc);
        tarFile.write(tarball.c_str(), tarball.length());
        tarFile.close();
    } catch (...) {
        return crow::response(500);
    }

    // untar the tarball

    string untarcmd("tar --extract --keep-newer-files --file=" + tarName);
    if (system(untarcmd.c_str()) != 0) {
        return crow::response(500);
    }

    // create a new tarball in the static tarball path
    string mktarcmd("tar cf " + tarDir + "/" + user + ".tar pwrules pwdb");
    if (system(mktarcmd.c_str()) != 0) {
        return crow::response(500);
    }
    cerr << "syncup: exec'd" << mktarcmd << endl;
    return crow::response(202); // Accepted.
}

void CloudSync::setupUser(const string& hexuser) {
    using namespace std;
    filesystem::path userDir(cloudDir + hexuser);
    filesystem::path cloudPath(cloudDir);
    filesystem::create_directory(userDir,cloudPath);
}
