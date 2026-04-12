#!/bin/bash

# Configuration Netplan pour IP Statique (192.168.56.200)
echo "network:" > /etc/netplan/99-static-ip.yaml
echo "  version: 2" >> /etc/netplan/99-static-ip.yaml
echo "  ethernets:" >> /etc/netplan/99-static-ip.yaml
echo "    enp0s8:" >> /etc/netplan/99-static-ip.yaml
echo "      dhcp4: false" >> /etc/netplan/99-static-ip.yaml
echo "      addresses:" >> /etc/netplan/99-static-ip.yaml
echo "        - 192.168.56.200/24" >> /etc/netplan/99-static-ip.yaml

# Application des changements
netplan apply
echo -e "\n✅ Super ! L'IP 192.168.56.200 a ete configuree avec succes sur enp0s8 !"
ip a | grep 192.168.56.200
