#! /bin/sh

strStatus=$(/root/scripts/ch/getStatus.sh)
if [ $strStatus == 'offline' ]
then
        /etc/init.d/cgminer start > /dev/null 2>&1
        sleep 1
        #echo "start"
        #exit 0
else
        echo "can't start since the status is not in 'offline' state"
        exit 0
fi

hostname=$(cat /etc/config/system | grep "^\s*[^# \t].*$" | grep hostname -m 1 | awk '{print $3}' | cut -c2-7)

if [ $hostname == 'MT7621' ]
then
        pid=$(ps | grep cgminer | grep -v grep | awk '{print $1}')
else
        pid=$(ps aux | grep cgminer | grep -v grep | awk '{print $2}')
fi
strStatus=$(/root/scripts/ch/getStatus.sh)
echo $strStatus

exit 0
