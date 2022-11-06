#! /bin/sh

cat /etc/config/cgminer | grep "^\s*[^# \t].*$" | grep osc_clock -m 1 | awk '{print $3}'
