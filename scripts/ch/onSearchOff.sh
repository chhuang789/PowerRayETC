#! /bin/sh

hostname=$(cat /etc/config/system | grep "^\s*[^# \t].*$" | grep hostname -m 1 | awk '{print $3}' | cut -c2-7)

if [ $hostname == 'MT7621' ]
then
        /root/scripts/ch/7621_search-off.sh
else
        /root/scripts/ch/1619_search-off.sh
fi

exit 0
