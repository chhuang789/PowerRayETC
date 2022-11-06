#! /bin/sh

python3 /root/ft930_control/flash_control.py --erase-chip --d2xx-port 1 --verbose
python3 /root/ft930_control/flash_control.py --erase-chip --d2xx-port 5 --verbose
python3 /root/ft930_control/flash_control.py --erase-chip --d2xx-port 9 --verbose
python3 /root/ft930_control/flash_control.py --erase-chip --d2xx-port 13 --verbose
