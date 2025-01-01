#!/bin/sh

# Dependencies
sudo apt install libasio-dev libsodium-dev
make
sudo cp bcpwm-server /usr/sbin/
sudo chown root:root /usr/sbin/bcpwm-server
sudo chmod 755 /usr/sbin/bcpwm-server

# Add certs to global dir
sudo mkdir -p /etc/bci/bci-cert
sudo cp cert.pem /etc/bci/bci-cert/bcpwm.pem
sudo cp key.pem /etc/bci/bci-cert/bcpwm-key.pem

# Create global dirs
sudo mkdir -p /var/bcpwm
sudo mkdir -p /var/bcpwm/tar
sudo mkdir -p /var/bcpwm/rules
sudo cp register_rule.html /var/bcpwm/
sudo cp -r sql_scripts /var/bcpwm/
head -c 32 /dev/urandom >confirmkey
sudo cp confirmkey /var/bcpwm/


# Install as systemd service
sudo cp bcpwm.service /etc/systemd/system/
sudo chown root:root /etc/systemd/system/bcpwm.service
sudo chmod 644 /etc/systemd/system/bcpwm.service

# for testing install only: point bcpwm.badlycoded.net to 127.0.0.1

grep -v "bcpwm.badlycoded.net" /etc/hosts > hosts.install
cat hostline >> hosts.install
sudo cp --force hosts.install /etc/hosts
