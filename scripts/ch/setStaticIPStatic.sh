#! /bin/sh

rm -rf /root/tmp?.txt

strLine=$1
nLine1=$((strLine + 1))
nLine2=$((nLine1 + 5))

sed -i ${nLine1}s/dhcp/static/ /etc/config/network

echo -e "\toption ipaddr '$2'" > /root/tmp2.txt
echo -e "\toption netmask '$3'" >> /root/tmp2.txt
echo -e "\toption gateway '$4'" >> /root/tmp2.txt
echo -e "\toption dns '$5'" >> /root/tmp2.txt
head -n $nLine1 /etc/config/network > /root/tmp1.txt
tail -n+$nLine2 /etc/config/network > /root/tmp3.txt

cat /root/tmp1.txt > /etc/config/network
cat /root/tmp2.txt >> /etc/config/network
cat /root/tmp3.txt >> /etc/config/network

/etc/init.d/network restart

exit
