#!/bin/bash

echo "Configuring iptables to ignore tcp connections and udp connections"

sudo iptables -A INPUT -p tcp --tcp-flags RST RST -j DROP
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo iptables -A OUTPUT -p icmp --icmp-type destination-unreachable -j DROP

echo "Disabling built-in Linux NTP"
sudo systemctl stop systemd-timesyncd
sudo systemctl disable systemd-timesyncd
sudo systemctl mask systemd-timesyncd
