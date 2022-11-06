#! /bin/sh

cat /etc/config/cgminer | grep "^\s*[^# \t].*$" | grep etcpool1url -m 1 | awk '{print $3}'
cat /etc/config/cgminer | grep "^\s*[^# \t].*$" | grep pool1wallet -m 1 | awk '{print $3}'
cat /etc/config/cgminer | grep "^\s*[^# \t].*$" | grep pool1pw -m 1 | awk '{print $3}'
cat /etc/config/cgminer | grep "^\s*[^# \t].*$" | grep osc_clock -m 1 | awk '{print $3}'
cat /etc/config/system | grep "^\s*[^# \t].*$" | grep hostname -m 1 | awk '{print $3}'