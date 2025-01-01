#!/bin/sh
grep -v "bcpwm.badlycoded.net" /etc/hosts > hosts.install
cat hostline >> hosts.install
sudo cp --force hosts.install /etc/hosts

