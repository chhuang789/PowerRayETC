#! /bin/sh

/etc/init.d/cgminer stop

hostname=$(cat /etc/config/system | grep hostname | awk '{print $3}' | cut -c2-7)
echo "hostname="$hostname

i=1
if [ $hostname == 'MT7621' ]
then
        pid=$(ps | grep cgminer | grep -v grep | awk '{print $1}')
else
        pid=$(ps aux | grep cgminer | grep -v grep | awk '{print $2}')
fi
while true; do
        if [[ "$i" -gt 10 ]]; then
                echo "/etc/init.d/cgminer stop more than 10 seconds. Force kill -9" $pid
                kill -9 $pid
                break
        fi
        let "i++"
        sleep 1

        if [ $hostname == 'MT7621' ]
        then
                ps=1
                a=$(echo `ps | grep cgminer | grep -v grep`)
        else
                ps=2
                a=$(echo `ps aux | grep cgminer | grep -v grep`)
        fi
        if [ $ps == 1 ]
        then
                if ps | grep cgminer | grep -v grep > /dev/null
                then
                        k=1
                else
                        break
                fi
        else
                if [ ${#a} -gt 0 ]
                then
                        k=1
                else
                        break
                fi
        fi
done

n=`expr "$1" : "$1"`
if [ $n != 2 ]
then
	A=$(cat /etc/config/cgminer | grep "^\s*[^# \t].*$" | grep etcpool1url -m 1 | awk '{print $3}')
	OLD=$(echo $A | sed 's,/,\\/,g')
	B=$1
	NEW=$(echo $B | sed 's,/,\\/,g')
	sed -i s/$OLD/$NEW/ /etc/config/cgminer
fi

n=`expr "$2" : "$2"`
if [ $n != 2 ]
then
        A=$(cat /etc/config/cgminer | grep "^\s*[^# \t].*$" | grep pool1wallet -m 1 | awk '{print $3}')
        OLD=$(echo $A | sed 's,/,\\/,g')
        B=$2
        NEW=$(echo $B | sed 's,/,\\/,g')
        sed -i s/$OLD/$NEW/ /etc/config/cgminer
fi

n=`expr "$3" : "$3"`
if [ $n != 2 ]
then
        A=$(cat /etc/config/cgminer | grep "^\s*[^# \t].*$" | grep pool1pw -m 1 | awk '{print $3}')
	OLD=$(echo $A | sed 's,/,\\/,g')
        B=$3
        NEW=$(echo $B | sed 's,/,\\/,g')
        sed -i s/$OLD/$NEW/ /etc/config/cgminer
fi

/etc/init.d/cgminer start

if [ $hostname == 'MT7621' ]
then
        pid=$(ps | grep cgminer | grep -v grep | awk '{print $1}')
else
        pid=$(ps aux | grep cgminer | grep -v grep | awk '{print $2}')
fi
echo "New PID="$pid
