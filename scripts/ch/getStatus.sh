#! /bin/sh

sec=$(awk '{print $1}' /proc/uptime | awk -F'.' '{print $1}')

if [ -z "$1" ]
then
        if [ $sec -lt $1 ]
        then
                echo "booting"
                exit 0
        fi
fi

hostname=$(cat /etc/config/system | grep "^\s*[^# \t].*$" | grep hostname -m 1 | awk '{print $3}' | cut -c2-7)

if [ $hostname == 'MT7621' ]
then
        ps=1
                ioscan=$(ps w w | grep "run-io-scan" | grep -v grep | wc -l)
                cgminer=$(ps w w | grep cgminer | grep -v "run-io-scan" | grep -v grep | wc -l)
                if [[ $ioscan -ge 1 && $cgminer -ge 1 ]]; then
                        echo "FailCode,3,IOSCAN and Mining are both in the same time"
                fi
else
        ps=2
		a=$(echo `ps aux | grep cgminer | grep -v grep`)
fi
if [ $ps == 1 ]
then
        if ps | grep cgminer | grep -v grep > /dev/null
        then
                status='found'
        else
                status='offline'
                echo $status
                exit 0
        fi
else
        if [ ${#a} -gt 0 ]
        then
                status='found'
        else
                status='offline'
                echo $status
                exit 0
        fi
fi

if [ $ps == 1 ]
then
        if ps | grep -- 'run-io-scan' | grep -v grep > /dev/null
        then
                        status='IOSCAN'
                        echo $status
                        for i in $(ls /tmp/mining_scan_?_1.log); do
                                echo $(cat $i | grep Testing | wc -l)
                        done
                        exit 0
        else
                        status='DAGorMining?'
        fi
else
        if ps aux | grep -- 'run-io-scan' | grep -v grep > /dev/null
        then
                        status='IOSCAN'
                        echo $status
                        for i in $(ls /tmp/log/mining_scan?_?.log); do
                                echo $(cat $i | grep Testing | wc -l)
                        done
                        exit 0
        else
                        status='DAGorMining?'
        fi
fi

if [ $ps == 1 ]
then
        if ps | grep -- 'cgminer -o stratum+tcp' | grep -v grep > /dev/null
        then
                        if tail -100 /tmp/log/messages | grep "Write dag entry" > /dev/null
                        then
                                        status='DAG'
                                        echo $status
                        else
                                        status='Mining'
                                        echo $status
                        fi
        else
                        status='unknown'
                        echo $status
                        exit 0
        fi
else
        if ps aux | grep -- 'cgminer -o stratum+tcp' | grep -v grep > /dev/null
        then
                        if tail -100 /root/log/messages | grep "Write dag entry" > /dev/null
                        then
                                        status='DAG'
                                        echo $status
                        else
                                        status='Mining'
                                        echo $status
                        fi
        else
                        status='unknown'
                        echo $status
                        exit 0
        fi
fi

if [ $status == 'DAG' ]
then
        if [ $ps == 1 ]
        then
                tail -100 /tmp/log/messages | grep -m 8 "Write dag entry"
        else
                tail -100 /root/log/messages | grep -m 8 "Write dag entry"
        fi
fi

exit 0
