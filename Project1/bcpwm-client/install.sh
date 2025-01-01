#!/bin/sh

# dependencies
sudo apt install libsodium-dev
make all
# installation
sudo cp bcpwm-cli /usr/bin
sudo chown root:root /usr/bin/bcpwm-cli
sudo chmod 755 /usr/bin/bcpwm-cli

# downgrade tar to avoid bug in --keep-newer-files
wget http://launchpadlibrarian.net/592959765/tar_1.34+dfsg-1build3_amd64.deb
sudo dpkg -i tar_1.34+dfsg-1build3_amd64.deb

# trust the certificate for the bcpwm server
sudo cp cert.pem /usr/local/share/ca-certificates/bcpwm.crt
sudo update-ca-certificates
# copy the certificate to global directory
sudo mkdir -p /etc/bci/bci-cert
sudo cp cert.pem /etc/bci/bci-cert/bcpwm.pem 

# just for testing purposes
sudo sh -c 'echo "10.32.102.69\tbcpwm.badlycoded.net" >>/etc/hosts'
