#! /bin/sh

strLine=$1
nLine1=$((strLine + 1))
nLine2=$((nLine1 + 1))

sed -i ${nLine1}s/static/dhcp/ /etc/config/network

sed -i ${nLine2}d /etc/config/network
sed -i ${nLine2}d /etc/config/network
sed -i ${nLine2}d /etc/config/network
sed -i ${nLine2}d /etc/config/network

exit
