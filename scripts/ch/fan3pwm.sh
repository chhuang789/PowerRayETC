#! /bin/bash

if [ -z $1 ]
then
	echo "Please specify RPM percentage"
	exit 1
fi

rpm=$1
index=2

/root/test/runfanpwm.sh $index $rpm

exit 0

