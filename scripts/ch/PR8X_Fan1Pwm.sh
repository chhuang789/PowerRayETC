#! /bin/bash

if [ -z $1 ]
then
        echo "Please specify Duty index"
        exit 1
fi

duty=$1

echo 1 > /sys/devices/platform/soc@0/98000000.rbus/98007000.syscon/980070d0.pwm/pwm_enable0
echo $duty > /sys/devices/platform/soc@0/98000000.rbus/98007000.syscon/980070d0.pwm/duty_rate0
