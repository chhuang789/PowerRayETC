#! /bin/sh

cat /etc/config/cgminer | grep "^\s*[^# \t].*$" | grep pool1wallet -m 1 | awk '{print $3}'