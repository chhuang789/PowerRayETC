#! /bin/sh

hostname=$(cat /etc/config/system | grep "^\s*[^# \t].*$" | grep hostname -m 1 | awk '{print $3}' | cut -c2-7)

sec=$(awk '{print $1}' /proc/uptime | awk -F'.' '{print $1}')

IOSCAN="OK"

if [ $sec -gt $1 ]
then
        IOSCAN="4hr"
fi

# print the MAC address of br-lan
strMAC=$(ifconfig | grep 'br-lan' | awk '{print $5}')
echo $strMAC

# print the worker name
if [ $hostname == 'MT7621' ]
then
        ps=1
        a=$(ps w | grep cgminer | grep -m 1 192 | grep -v grep | awk '{print $1}')
        b=$(echo /proc/${a}/cmdline)
        e=$(cat $b | awk -F":"  '{print $1}' | grep 192 | awk -F"." '{print $2}')
                #a=$(ps w | grep cgminer | grep -v grep | awk '{print $9}' | awk -F"." '{print$2}' | awk -F":" '{print$1}')
else
        ps=2
        a=$(ps aux w w | grep cgminer | grep -v grep | awk '{print $13}')
        if [ "$a" == "--run-io-scan" ]; then
                e="IOSCAN"
        else
                e=$(ps aux w w | grep cgminer | grep -v grep | awk '{print $15}' | awk -F"." '{print$2}' | awk -F":" '{print$1}')
        fi
fi
echo $e

echo $IOSCAN

exit 0