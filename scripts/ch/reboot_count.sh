#! /bin/sh

strDate=$(date '+%Y-%m-%d-%H-%M-%S')
FILE="/root/ServerID"

if [ -f "$FILE" ]; then
        strServerID=$(cat /root/ServerID)
else
        strServerID=$(ifconfig | grep 'br-lan' | awk '{print $5}')
fi

strFilename="$strServerID""-""$strDate"".txt"
echo $strFilename >> /root/reboot.txt

strIP=$(ifconfig br-lan | grep "inet " | awk '{print $2}' | awk -F: '{
print $2}')

strIP3=$(echo $strIP | cut -d "." -f 1,2,3)
strJSIP="$strIP3.2"
#strJSIP=$strIP
cmd=$(ssh -y -f root@$strJSIP "mkdir -p /root/reboot && echo 1 > /root/reboot/$strFilename")
exit 0
