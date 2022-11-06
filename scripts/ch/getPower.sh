#! /bin/sh

strZero="0"

hostname=$(cat /etc/config/system | grep hostname | awk '{print $3}' | cut -c2-7)

strBoard=$(cat /root/Model)

if [ $strBoard == "PR_8X" ]
then
    python3 /root/scripts/ch/PMBus.py &>/dev/null
    if [ "$?" == "$strZero" ]; then
            python3 /root/scripts/ch/PMBus.py | grep Power | awk '{print $3}'
    else
            echo "NA"
    fi
else
    if [ $hostname == 'MT7621' ]
    then
        echo "NA"
    else
        python3 /root/scripts/ch/PMBus.py &>/dev/null
        if [ "$?" == "$strZero" ]; then
                python3 /root/scripts/ch/PMBus.py | grep Power | awk '{print $3}'
        else
                echo "NA"
        fi
    fi
fi