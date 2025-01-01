#  bcpwm-server

This is the (pre-alpha release) cloud server code for BCPWM, the Badly Coded PassWord Manager.  

The file `server.cpp` contains the code that starts a CrowCPP app and sets up "routes" for the various requests the cloud server handles.  The application can be built using `make`, resulting in an executable named `bcpwm-server` and the `install.sh` script will fetch the necessary dependencies, create the expected directory structure, and install the server as a `systemd` service.  It will also installs a routing rule pointing the domain name `bcpwm.badlycoded.net` to `localhost`.  Once installed, you can start the server using `systemctl start bcpwm`, stop it using `systemctl stop bcpwm`, and see its output logs with `journalctl -u bcpwm`. (Google can help you find more information about interacting with systemd services.)

The `regdb.cpp` module contains the C++ code for handling registration functions: initializing user registrations, sending email confirmation codes, and checking user passwords.  It also contains code that allows website administrators to upload compiled `.bcr` files for their sites: you can start the process by opening a browser on the installed machine and browsing to `https://bcpwm.badlycoded.net/register_rule`.  (You can build a script to compile `.bcr` files from the `pwrules.c` module in bcpwm-client)

The `sql_scripts` directory contains the code that manages the sql(ite(3)) database of user registrations, confirmation codes, and rule file uploads.

The `cloudsync.cpp` module contains the code that manages synchronization of user password databases. 

Note: running `install.sh` on a machine that also has the pre-alpha bcpwm-cli code installed will prevent bcpwm-cli from communicating with the previous testing server.  This version of the server runs on the standard TLS port 443, so to interact with it via `bcpwm-cli`, you will need to change any URLs with `:453` in them to remove the `:453` and recompile.
