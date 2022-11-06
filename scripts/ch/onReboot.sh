#!/bin/sh

n=`expr "$1" : "$1"`

strStatus=$(/root/scripts/ch/getStatus.sh)
if [ $strStatus == 'Mining' ]
then
        /etc/init.d/cgminer stop > /dev/null 2>&1
else
        echo "Status="%strStatus
fi

i=0
while true; do
        i=$((i+1));
        strStatus=$(/root/scripts/ch/getStatus.sh)
        if [ $strStatus == 'offline' ]
        then
                echo $strStatus
                sync
                reboot
                echo "reboot"
                exit 0
        else
                sleep 1s
                if [ $i -eq $1 ]
                then
                        #echo "can't reboot since the status is not 'offline' state"
                        hostname=$(cat /etc/config/system | grep "^\s*[^# \t].*$" | grep hostname -m 1 | awk '{print $3}' | cut -c2-7)

                        if [ $hostname == 'MT7621' ]
                        then
                                pid=$(ps | grep cgminer | grep -v grep | awk '{print $1}')
                        else
                                pid=$(ps aux | grep cgminer | grep -v grep | awk '{print $2}')
                        fi

                        if [ ${#pid} -gt 0 ]
                        then
                                #echo $pid" is still in ps. For kill it and then reboot"
                                kill -9 $pid
                                sleep 2
                                strStatus=$(/root/scripts/ch/getStatus.sh)
                                echo $strStatus
                        fi
                        break
                fi
        fi
done

sync
reboot
echo "reboot"
exit 0