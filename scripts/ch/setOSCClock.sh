#! /bin/sh

strIP=$(ifconfig br-lan | grep "inet " | awk '{print $2}' | awk -F":" '{print $2}')

n=`expr "$1" : "$1"`
if [ $n != 2 ]
then
	A=$(cat /etc/config/cgminer | grep osc_clock | awk '{print $3}')
	OLD=$(echo $A | sed 's,/,\\/,g')
	B="'${1}'"
	NEW=$(echo $B | sed 's,/,\\/,g')
	if [ $OLD == $NEW ]
	then
		echo $strIP" no change for OSC clock. So, do nothing."
	else
		echo $strIP" change OSC Clock from " + $OLD + " to " + $NEW + " and then reboot"
		sed -i s/$OLD/$NEW/ /etc/config/cgminer
		/root/scripts/ch/onReboot.sh
	fi
fi
