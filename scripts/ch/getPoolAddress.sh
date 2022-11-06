#! /bin/sh

cat /etc/config/cgminer | grep "^\s*[^# \t].*$" | grep etcpool1url -m 1 | awk '{print $3}'
