#! /bin/sh

echo timer > /sys/devices/platform/leds/leds/green:standby/trigger
echo 33 > /sys/devices/platform/leds/leds/green:standby/delay_on

echo timer > /sys/devices/platform/leds/leds/red:fault/trigger
echo 13 > /sys/devices/platform/leds/leds/red:fault/delay_on
