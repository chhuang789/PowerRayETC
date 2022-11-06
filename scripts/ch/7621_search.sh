#! /bin/sh

devmem 0x1E000060 32 0x00008524

echo timer > /sys/class/leds/LED_Operational:green:GPIO_24/trigger
echo 33 > /sys/class/leds/LED_Operational:green:GPIO_24/delay_on

echo timer > /sys/class/leds/LED_Fault:red:GPIO_25/trigger
echo 13 > /sys/class/leds/LED_Fault:red:GPIO_25/delay_on
