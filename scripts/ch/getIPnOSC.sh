#! /bin/sh

PROTOCOL=$(cat /etc/config/network | grep "^\s*[^# \t].*$" | grep "'lan'" -A 7 | grep proto | awk '{print $3}')
echo ${PROTOCOL:1:-1}

IP=$(ifconfig br-lan | grep "inet " | awk -F ":" '{print $2}' | awk '{print $1}')
echo $IP

NETMASK=$(ifconfig br-lan | grep "inet " | awk -F ":" '{print $4}')
echo $NETMASK

GATEWAY=$(ip route show | grep -m 1 default | awk '{print $3}')
echo $GATEWAY

DNS=$(cat /etc/resolv.conf | grep "^\s*[^# \t].*$" | grep -m 1 nameserver | awk '{print $2}')
echo $DNS

OSC_CLOCK=$(cat /etc/config/cgminer | grep "^\s*[^# \t].*$" | grep osc_clock -m 1 | awk '{print $3}')
echo $OSC_CLOCK
