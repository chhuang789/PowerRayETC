#! /bin/sh

devmem 0x1E000060 32 0x00008524

echo none > /sys/class/leds/LED_Operational:green:GPIO_24/trigger

echo none > /sys/class/leds/LED_Fault:red:GPIO_25/trigger

