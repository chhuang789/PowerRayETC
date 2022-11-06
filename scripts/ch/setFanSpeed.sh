#! /bin/sh

if [ -z $1 ]
then
        echo "Please specify FAN duty percentage. For example 50, 60, 70, 80, 90 or 100"
        exit 1
fi

rpm=$1

strBoard=$(cat /root/Model)
if [ $strBoard == "PR_8X" ]; then
    /root/test/runfanpwm.sh 0 $rpm
    /root/test/runfanpwm.sh 1 $rpm
    echo "Change fan speed done!"
else
    echo "Not PR_8X model. Ignore this command."
fi
