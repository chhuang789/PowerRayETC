#! /bin/sh

strZero="0"

hostname=$(cat /etc/config/system | grep hostname | awk '{print $3}' | cut -c2-7)

strBoard=$(cat /root/Model)
if [ $strBoard == "PR_8X" ]; then
    (python3 /root/scripts/ch/PR8X_fan_detect.py 1)  &>/dev/null
    if [ "$?" == "$strZero" ]; then
        python3 /root/scripts/ch/PR8X_fan_detect.py 1 | grep PWM | awk '{print$3}'
        python3 /root/scripts/ch/PR8X_fan_detect.py 2 | grep PWM | awk '{print$3}'
    else
        echo "NA"
        echo "NA"
    fi
    echo "NA"
    echo "NA"
    python3 /root/scripts/ch/PMBus.py &>/dev/null
    if [ "$?" == "$strZero" ]; then
        python3 /root/scripts/ch/PMBus.py | grep 'Fan Speed' | awk '{print $3}'
    else
        echo "NA"
    fi
else
    echo "NA"
    echo "NA"
    echo "NA"
    echo "NA"
    if [ $hostname == 'MT7621' ];then
        echo "NA"
    else
        python3 /root/scripts/ch/PMBus.py &>/dev/null
        if [ "$?" == "$strZero" ]; then
            python3 /root/scripts/ch/PMBus.py | grep 'Fan Speed' | awk '{print $3}'
        else
            echo "NA"
        fi
    fi
fi
