#! /bin/sh

strBoard=$(cat /root/Model)
if [ $strBoard == "PR_8X" ]
then
    python3 /root/ft930_control/FT930_control.py --d2xx-port 1 --report-readings --hashboard | grep -i "board temp" | awk '{print $4}'
    python3 /root/ft930_control/FT930_control.py --d2xx-port 5 --report-readings --hashboard | grep -i "board temp" | awk '{print $4}'
    python3 /root/ft930_control/FT930_control.py --d2xx-port 9 --report-readings --hashboard | grep -i "board temp" | awk '{print $4}'
    python3 /root/ft930_control/FT930_control.py --d2xx-port 13 --report-readings --hashboard | grep -i "board temp" | awk '{print $4}'
elif [ $strBoard == "PR_1U" ]
then
    python3 /root/ft930_control/FT930_control.py --d2xx-port 1 --report-readings --hashboard | grep -i "board temp" | awk '{print $4}'
else
    python3 /root/ft930_control/FT930_control.py --d2xx-port 1 --report-readings --hashboard | grep -m 1 -i "board temp" | awk '{print $4}'
    python3 /root/ft930_control/FT930_control.py --d2xx-port 5 --report-readings --hashboard | grep -m 1 -i "board temp" | awk '{print $4}'
fi
