# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# source /Users/chhuang789/redfish_advantech_library/redfish/bin/activate
# v0.99 from v0.98:
#   1. Add debug log
#   2. Add MSSQL and modify MySQL database in both python file and config.json
# v1.00 add more log
# v1.01 add log for DB Rollback issue. PowerConsumption to short set from char(5) to char(7). And add exception handling of MySQLdb.Error
#       ALTER TABLE `PowerRayETC`.`scan` CHANGE `PowerConsumption` `PowerConsumption` char(7) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT NULL;
# v1.02
#   1. Limit the size of each field to avoid MySQLdb.Error 1406: Data too long for column 'xxx' at row 1 (MariaDB)
#   2. Handle known host exist and conflict in known_hosts (Windows)
# v1.03
#   1. 1. 輸入多少個，若有失敗也要產生出來，並註明原因 (Ron)
#   2. 給一個礦機IP List file, 可以import進來，並只針對這些礦機做scan (Mark)
#   3. 再給一台機器來裝程式 (David)
#   4. Fix bugs and add features
#     4.1 File "C:\Users\Administrator\ch\PowerRayETC-1.0.2.py", line 619, in onScan
#         if strTmp[-1] == "\n":
#         IndexError: string index out of range
#         if strTmp[-1] == "\n": --> if len(strTmp) > 0 and strTmp[-1] == "\n": # 先判斷strTmp長度>0
#     4.2 cmd3 = r"C:\windows\system32\Openssh\ssh-keygen.exe -R " + strIP + " > $null"
#     4.3 sshToWoker reuturn 2 varaiables, the 1st one is sshClient, the 2nd one is the string if ssh failed.
#     4.4 w.FailCode == 0 normal white, FailCode > 0 with error as:
#           1: red for worker not match to IP or IOSCAN has some issue
#           2: yellow for ssh/scp error
#           3: IOSCAN and Mining in the same worker
#           4: no cgminer found -> offline
#           5: ssh to IP timeout
#           6: exec command fail
#           7: PMBus error # "Build Version=20221031-002"
#           99: Unknown execption
#       4.4.1 Add FailCode = char(1), default='0'. FailDesc=varchar(50), default=NULL
#       4.4.2 ALTER TABLE `scan` ADD COLUMN `FailCode` CHAR(1) DEFAULT '0' COLLATE 'utf8mb4_general_ci' AFTER `BoardTemp8`, ADD COLUMN `FailDesc` VARCHAR(50) NULL DEFAULT NULL COLLATE 'armscii8_general_ci' AFTER `FailCode`;
#       4.4.3
#           # mysql -u root -p
#           Enter password: xxxxxx
#           MariaDB [(none)]> use PowerRayETC;
#           MariaDB [(none)]> ALTER TABLE `scan` ADD COLUMN `FailCode` CHAR(1) DEFAULT '0' COLLATE 'utf8mb4_general_ci' AFTER `BoardTemp8`, ADD COLUMN `FailDesc` VARCHAR(50) NULL DEFAULT NULL COLLATE 'armscii8_general_ci' AFTER `FailCode`;
#           MariaDB [PowerRayETC]> desc scan;
'''
+------------------+-------------+------+-----+---------------------+----------------+
| Field            | Type        | Null | Key | Default             | Extra          |
+------------------+-------------+------+-----+---------------------+----------------+
| id               | int(11)     | NO   | PRI | NULL                | auto_increment |
| batch_id         | int(11)     | NO   |     | NULL                |                |
| datetime         | datetime    | NO   | MUL | current_timestamp() |                |
......
| BoardTemp8       | char(4)     | YES  |     | NULL                |                |
| FailCode         | char(1)     | YES  |     | 0                   |                |
| FailDesc         | varchar(50) | YES  |     | NULL                |                |
+------------------+-------------+------+-----+---------------------+----------------+
42 rows in set (0.011 sec)
'''
#     4.5 logging filename by datetime (Change the logging.conf)
#       [handler_fileHandler]
#       class=FileHandler
#       args=(__import__("datetime").datetime.now().strftime('%%Y-%%m-%%d_%%H_%%M.log'), 'a')
#       Add more log
#     4.6 Add filed to note error message for abnormal worker
#     4.7 Note that 2 cgminers in the process with different status. Example: 1 in miner and the other one in IOSCAN
#       root@MT7621_SB:~# ps | grep cgminer | grep -v grep -wc
#       2
#       root@MT7621_SB:~# ps | grep cgminer | grep -v grep
#       4059 root     96268 S    cgminer --factory-test --run-io-scan --port-path 1 --skip-set-osc-clock --output-file /root/asic_info/bad_dram_list_all_page1.txt --target-page 8 --solutions 1 --
#       4708 root      221m S<   cgminer -o stratum+tcp://asia1-etc.ethermine.org:4444 -O 20c0ac4e73ed4db87fef692991c0f4becff93cbc.192-168-66-147:1234 --api-allow W:127.0.0.1 --api-listen --evb-m
#     4.8 Please add the follow lines in config.json for each showxxx
#         "FailCode": "1",
#         "FailDesc": "1"
#
# v1.04
#   1. Load IPv4 List, one text column with all the IPv4 list to be scan. And should show all result no matter it's success or fail
# v1.05
#   1. Seperate load IPv4 list from file and Scan IPv4 list
#   SOP:
#   A. Upgrade to v1.05
#   config.json readme:
#   B. Put ip list txt file in the same directory as PowerRayETC-<ver>.py
#   C. Change the "Home" as "0" in the production site. = "1" in none production site
#   D. Change "Verbose" as "1" for more debug information. As "0" to minize the debug information
#   E. Change "Test" as "1" to get the latest IP from the web to replace the test bed worker into the database
#   F. "Debug" = 0: DEBUG, INFO, WARNING, ERROR, CRITICAL
#                1: INFO, WARNING, ERROR, CRITICAL
#                2: WARNING, ERROR, CRITICAL
#                3: ERROR, CRITICAL
#                4: CRITICAL
# .  G. Copy PowerRayETC-1.05.py to server
#   logging.conf readme: (Please keep level of paramiko [ssh] to INFO if you need more ssh debug information. Other parameters, please do not change it if no need)
#   [logger_paramiko]
#   level=INFO
#   Copy all scripts to the Windows or any other machine which want to run this program
#
#   v1.06
#   A. Change  " > $null" to " 2>&1 | out-null" for WIndows Platform
#   B. Add more log when runn "chmod +x ..." on remote worker
#   C. Add offline FailCode=4 and FailDesc="no cgminer found -> offline" and change green to lighgreen color
#   D. Change the log file to log directory. The max size of bytes is 52428800 (50MB) for each log file. And up to 10 backup log files. After reach the max log files. The logging will overwrite the 1st one.
#       Change the logging.con
#   E. Modify the fan duty for 50/60/70/80/90/100. The default valude is 80.
#       Change the config.json
#   v1.07 Performance improvement
#       A. Try multi-thread on fan duty change progress (TBD)
#       B. Avoid ssh warning message to add following lines in $HOME\.ssh\config
#           > cat $HOME\.ssh\config
#           Host *
#               StrictHostKeyChecking no
#       C. Show less information when find CA finger error
#       D. Add one more error 7 for PMBus error # "Build Version=20221101-001"
#       E. Fix the problem that export missed BoardTemp8 and add 2 fileds FailCode and FailDesc # "Build Version=20221102-001"
#       F. # Change datetime from batch datetime to scan datetime for "Build Version=20221102-001"
#   v1.08 Change from web crwawl to API call
#       A. Change from web crwawl to API call "Build Version=20221103-001"
#       B. Change all workerArray[i].datetime as now() when start to scan "Build Version=20221105-003"


import ctypes
import json
import logging.config  # 0.99.1
import os
import platform
import re
import socket
import subprocess
import threading
import time
import tkinter as tk
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler  # 1.03 rotation logging
from pathlib import Path, PureWindowsPath
from time import sleep
from tkinter import LEFT, filedialog, messagebox, ttk
from xmlrpc.client import Transport

import MySQLdb
import paramiko
import pymssql
from bs4 import BeautifulSoup
from paramiko import SSHClient
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service
from tkcalendar import DateEntry

from ethermine import *

logger = None
logging.basicConfig(level=logging.WARNING)
POWERRAY_ETC_VERSION = 1.08
POWERRAY_ETC_BUILD_VERSION = "Build Version=20221105-004"

strLogFormater1 = None
strLogFormater2 = None
FHLog = None
bLevelname = False


class worker():
    def __init__(self):
        self.Number = 0
        self.UP = 0
        self.Web = 0  # if the IP exist in the web site
        self.Hostname = None
        self.Model = None
        self.IP = None
        self.Worker = None
        self.MAC = None
        self.ServerID = None
        self.Status = None
        self.Progress = []
        self.PoolHashRate = None
        self.SelfCalHashRate = 'NA'
        self.HashboardAsic = [[0, 0], [0, 0], [0, 0], [0, 0]]
        self.WorkingAsic = 0
        self.FanSpeed = []
        self.PoolAddress = None
        self.WalletAddress = None
        self.Account = 'NA'
        self.Password = None
        self.MinerOPFreq = None
        self.PowerConsumption = None
        self.DHCPorFixedIP = 'NA'
        self.Temperature = []
        self.batch_id = 0
        self.datetime = datetime.now()
        self.bPowerRay = False
        self.FailCode = 0  # if the worker machine port 22 is open for ssh
        self.FailDesc = ""
        self.Ssh = 0


class Configuration():
    def __init__(self):
        self.IPs = []
        self.Scanning = None
        self.Refresh = None
        self.URL = []
        self.Pool = []
        self.Wallet = []
        self.Password = []
        self.Clock = []
        self.pr_8x_fan_duty = []
        self.mssqlHost = "192.168.1.5"
        self.mssqlPort = 1443
        self.mssqlUser = "test123"
        self.mssqlPassword = "test"
        self.mssqlStoreProcedure = "PowerRayETC"
        self.mysqlHost = "localhost"
        self.mysqlPort = 3306
        self.mysqlUser = "root"
        self.mysqlPassword = "Acl-123!"
        self.mysqlDatabase = "PowerRayETC"
        self.ShowAll = dict
        self.Show1 = dict
        self.Show2 = dict
        self.Show3 = dict
        self.Show4 = dict
        self.Show5 = dict
        self.scan = False
        self.Home = 0
        self.bScan = False
        self.StopTimeout = 100
        self.ScreenWidth = 1920
        self.ScreenHeight = 1080
        self.RootWidth = 1235
        self.RootnHeight = 750
        self.RootX = 10
        self.RootY = 10
        self.Debug = 0
        self.OSUsername = os.getenv("USER")
        self.KnownHosts = ''
        self.scpscripts = ''
        self.Test = False


strTestIP = ""  # only for myConfig.Test is True. Get the lastest IP from web.
# only for myConfig.Test is True. Get the lastest CurrentHashrate from web.
fTestCurrentHashrate = 0.0

dictIPtoIndex = {}  # mapping IP to index number as integer
nPlatform = 0  # 1: For Windows, 2: for MacOS 3: For other Linux
PATH_CONFIG = r"./config.json"
# For production's PATH_CONFIG for user in {"Administrator", "Ron", "Markl"}
# For test bed on CH's Mac {"chhuang789"}, CH's laptop {"chhuang789"}
if platform.system() == 'Windows':
    a = "\\"
    PATH_CONFIG = "C:\\Users\\" + os.getlogin() + a + "ch\\config.json"
elif platform.system() == 'Darwin':  # For my Mac's develop PATH_CONFIG
    # I don't understand whe os.getlogin() == "Root" even my username is "chhuang789"
    if os.getlogin().lower() in {"chhuang789", "root"}:
        PATH_CONFIG = r"config.json"
elif platform.system() == 'Linux':
    if os.getlogin().lower() == "root":
        PATH_CONFIG = r"/root/ch/config.json"


def readConfig(myConfig):
    with open(PATH_CONFIG, "r", encoding="utf-8-sig") as config_json:
        data = json.load(config_json)
    for i in data["IP Range"]:
        myConfig.IPs.append(i)
    myConfig.Scanning = data["Scanning Timeout"]
    myConfig.Refresh = data["Refresh Timeout"]
    myConfig.StopTimeout = data["Stop Timeout"]
    myConfig.Home = data["Home"]
    myConfig.Debug = data["Debug"]
    if myConfig.Debug == 0:
        logging.basicConfig(level=logging.DEBUG)
    elif myConfig.Debug == 1:
        logging.basicConfig(level=logging.INFO)
    elif myConfig.Debug == 2:
        logging.basicConfig(level=logging.WARNING)
    elif myConfig.Debug == 3:
        logging.basicConfig(level=logging.ERROR)
    elif myConfig.Debug == 4:
        logging.basicConfig(level=logging.CRITICAL)
    myConfig.Verbose = data["Verbose"]
    myConfig.Test = data["Test"]
    if myConfig.Test == 1:
        myConfig.Test = True
    myConfig.KnownHosts = data["Known_hosts"]
    myConfig.scpscripts = data["scp scripts"]
    for i in data["Pool"]:
        for j in i:
            myConfig.Pool.append(i[j])
    for i in data["Wallet"]:
        for j in i:
            myConfig.Wallet.append(i[j])
    for i in data["Password"]:
        for j in i:
            myConfig.Password.append(i[j])
    for i in data["OSC Clock"]:
        for j in i:
            myConfig.Clock.append(i[j])
    for i in data["URL"]:
        for j in i:
            myConfig.URL.append(i[j])
    for i in data["PR_8X_FAN_DUTY"]:
        for j in i:
            myConfig.pr_8x_fan_duty.append(i[j])
    myConfig.mssqlHost = data["MSSQL"][0]["host"]
    myConfig.mssqlPort = data["MSSQL"][0]["port"]
    myConfig.mssqlUser = data["MSSQL"][0]["user"]
    myConfig.mssqlPassword = data["MSSQL"][0]["password"]
    myConfig.mssqlDatabase = data["MSSQL"][0]["database"]
    myConfig.mssqlStoreProcedure = data["MSSQL"][0]["StoredProcedure"]

    myConfig.mysqlHost = data["MySQL"][0]["host"]
    myConfig.mysqlPort = data["MySQL"][0]["port"]
    myConfig.mysqlUser = data["MySQL"][0]["user"]
    myConfig.mysqlPassword = data["MySQL"][0]["password"]
    myConfig.mysqlDatabase = data["MySQL"][0]["database"]
    for i in data["Show All"]:
        myConfig.ShowAll = i
    for i in data["Show 1"]:
        myConfig.Show1 = i
    for i in data["Show 2"]:
        myConfig.Show2 = i
    for i in data["Show 3"]:
        myConfig.Show3 = i
    for i in data["Show 4"]:
        myConfig.Show4 = i
    for i in data["Show 5"]:
        myConfig.Show5 = i
    config_json.close()


myConfig = Configuration()
readConfig(myConfig)

# Default OS for MacOS(nPlatform=2) or Linux(nPlatform=3)
nWebdriver = 2  # For MacOS and Linux
PATH_APP_DIR = '~/ch'
# For MacOS and Linux shell: export PATH_APP_DIR=~/PowerRayETC; cd ${PATH_APP_DIR}
PATH_CONFIG = "./config.json"
PATH_WEBDRIVER = "./msedgedriver"
# For production's PATH_CONFIG, PATH_WEBDRIVER for user in {"Administrator", "Ron", "Markl"}
if platform.system() == 'Windows':
    nPlatform = 1
    nWebdriver = 1
    a = "\\"
    PATH_CONFIG = "C:\\Users\\" + os.getlogin() + a + "ch\\config.json"
    PATH_WEBDRIVER = "C:\\Users\\" + os.getlogin() + a + "ch\\msedgedriver.exe"
elif platform.system() == 'Darwin':  # For my Mac's develop PATH_CONFIG and PATH_WEBDRIVER
    nPlatform = 2
    # I don't understand whe os.getlogin() == "Root" even my username is "chhuang789"
    if myConfig.OSUsername.lower() == "chhuang789":
        PATH_CONFIG = r"./config.json"
        PATH_WEBDRIVER = r"./msedgedriver"
elif platform.system() == 'Linux':
    nPlatform = 3
    PATH_CONFIG = r"/root/ch/config.json"
    PATH_WEBDRIVER = r"/root/ch/msedgedriver"

if logger == None:
    print("%s OS=%s, Username=%s, PATH_CONFIG=%s"
          % (datetime.now().strftime('%Y/%m/%d %H:%M:%S'), platform.system(), os.getlogin(), PATH_CONFIG))
    print("%s PATH_WEBDRIVER=%s"
          % (datetime.now().strftime('%Y/%m/%d %H:%M:%S'), PATH_WEBDRIVER))

s = Service(PATH_WEBDRIVER)

columns = ("Model",
           "IP",
           "Worker",
           "MAC",
           "ServerID",
           "Status",
           "Progress1",
           "Progress2",
           "Progress3",
           "Progress4",
           "Progress5",
           "Progress6",
           "Progress7",
           "Progress8",
           "PoolHashRate",
           "SelfCalHashRate",
           "WorkingAsic",
           "FAN1",
           "FAN2",
           "FAN3",
           "FAN4",
           "FAN5",
           "PoolAddress",
           "WalletAddress",
           "Account",
           "Password",
           "MinerOPFreq",
           "PowerConsumption",
           "DHCPorFixedIP",
           "BoardTemp1",
           "BoardTemp2",
           "BoardTemp3",
           "BoardTemp4",
           "BoardTemp5",
           "BoardTemp6",
           "BoardTemp7",
           "BoardTemp8",
           "FailCode",
           "FailDesc")

# Make a regular expression
# for validating an Ip-address
regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''

# Define a function for
# validate an Ip addess


def check(Ip):

    # pass the regular expression
    # and the string in search() method
    if (re.search(regex, Ip)):
        logger.info("Valid Ip address")

    else:
        logger.info("Invalid Ip address")


def validate(P):
    test = re.compile(
        '(^\d{0,3}$|^\d{1,3}\.\d{0,3}$|^\d{1,3}\.\d{1,3}\.\d{0,3}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{0,3}$)')
    if test.match(P):
        return True
    else:
        return False


def ip_to_int(ip):
    """
    :type ip: str
    :rtype: int[]
    """

    x = ip.split(".")
    for i in range(len(x)):
        x[i] = int(x[i])
    return x


def onMinus():
    if len(listbox.curselection()) > 0:
        nDelItem = []
        for i in listbox.curselection():
            nDelItem.append(i)
        for i in reversed(nDelItem):
            logger.info("Delete item '%s'", listbox.get(i))
            myConfig.IPs.remove(myConfig.IPs[i])
            listbox.delete(i)


ip1 = None
ip2 = None


def onPlus():
    top = tk.Toplevel(root)
    top.attributes('-topmost', 'true')
    if nPlatform == 1:
        top.geometry("265x63")
    else:
        top.geometry("360x80")
    x = root.winfo_x()
    y = root.winfo_y()
    top.geometry("+%d+%d" % (x+200, y+200))
    top.title("New IP Range")
    tk.Label(top, text="From IP:").grid(row=0, column=0, sticky='e', padx=5)
    tk.Label(top, text="To IP:").grid(row=1, column=0, sticky='e', padx=5)
    varip1 = tk.StringVar()
    vcmd1 = root.register(validate)
    ipaddr1 = tk.Entry(top, textvariable=varip1, width=23,
                       validate='key', validatecommand=(vcmd1, '%P'))
    ipaddr1.grid(row=0, column=1, padx=5, pady=5)
    varip2 = tk.StringVar()
    vcmd2 = root.register(validate)
    ipaddr2 = tk.Entry(top, textvariable=varip2, width=23,
                       validate='key', validatecommand=(vcmd2, '%P'))
    ipaddr2.grid(row=1, column=1, padx=5, pady=5)

    def cancel_btn():
        top.destroy()
        top.update()

    def add_btn():
        ip1 = ipaddr1.get()
        ip2 = ipaddr2.get()
        strTmp = ip1 + " - " + ip2
        logger.info("Append '%s' to scan list", strTmp)
        listbox.insert('end', strTmp)
        myConfig.IPs.append({'From': ip1, 'To': ip2})
        cancel_btn()

    if nPlatform == 1:
        btnAdd = tk.Button(top, text="Add", width=5, command=add_btn)
        btnCancel = tk.Button(top, text='Cancel', width=5, command=cancel_btn)
    else:
        btnAdd = tk.Button(top, text="Add", width=2, command=add_btn)
        btnCancel = tk.Button(top, text='Cancel', width=2, command=cancel_btn)
    btnAdd.grid(column=2, row=0)
    btnCancel.grid(column=2, row=1)


# Note here that Tkinter passes an event object to onselect() of listbox
def onSelect(evt):
    w = evt.widget
    if len(w.curselection()) == 0:
        return
    if myConfig.Verbose:
        logger.info('The following item are selected:')
        for i in w.curselection():
            logger.info(w.get(i))

# Click check of "Select All"


def checkSelectAll():
    if varSelectAll.get() == 1:
        for i in range(listbox.size()):
            listbox.select_set(i)
        if myConfig.Verbose:
            logger.info('The following item are selected:')
            for i in listbox.curselection():
                logger.info(listbox.get(i))
    else:
        for i in range(listbox.size()):
            listbox.select_clear(i)
        if myConfig.Verbose:
            logger.info('No item is selected:')


workerArray = []

# Click "Scan" btnAuto to trigger onScan function

onScanT0 = None  # Start datetime of worker scanning
onScanT1 = None  # End datetime of worker scanning


def onScan():
    if action.scan:  # if action.scan == True. The onScan will not running. Default action.scan is False.
        return
    action.scan = True  # Set to True to protect onScan running again.
    workerArray.clear()  # array of worker. Clear it before scaning.
    # dictionary mapping IP to index in workerArray. Clear it before scaning.
    dictIPtoIndex.clear()
    #btnScan.config(fg='red', bg='yellow')
    # sleep(1)
    j = 0
    # Scan only for selection IP Ranges
    onScanT0 = datetime.now()
    nCount = 0
    logger.info(
        "====== Scan all selected IPv4 range with port 22 open and valid worker's MAC address")
    for i in listbox.curselection():
        # Get the 'From' IP and 'To' IP strings of the selection IP Ranges
        strFrom = myConfig.IPs[i]['From']
        strTo = myConfig.IPs[i]['To']
        # Change IPv4 from String to 4 integers array
        lstFrom = ip_to_int(strFrom)
        lstTo = ip_to_int(strTo)
        # Warning when IP is not valid IPv4
        if len(lstFrom) != 4 or len(lstTo) != 4:
            messagebox.showwarning(
                title="Warning", message="FromIP(" + strFrom + ") or ToIP(" + strTo + ") is not valid")
            action.scan = False
            return
        # Warning when 'From' IP and 'To' IP not in the same class C
        if lstFrom[0] != lstTo[0] or lstFrom[1] != lstTo[1] or lstFrom[2] != lstTo[2]:
            messagebox.showwarning(
                title="Warning", message="FromIP(" + strFrom + ") or ToIP(" + strTo + ") is not in the same class C")
            action.scan = False
            return
        # Warning when 'From' IPv4 < 'To' IPv4
        if lstFrom[3] > lstTo[3]:
            messagebox.showwarning(
                title="Warning", message="FromIP(" + strFrom + ") >= ToIP(" + strTo + ")")
            action.scan = False
            return
        # Construct nmap command for Windows OS (nPlatform==1) and other OSs. Only check ssh port == 22
        # grep nmap result only for IP and ssh
        if nPlatform == 2 or nPlatform == 3:
            if myConfig.Home:
                strNmap = "sudo nmap -n -p 22 " + strFrom + "-" + \
                    str(lstTo[3]) + " | grep '" + \
                    str(lstFrom[0]) + "\\|ssh'"
            else:
                strNmap = "sudo nmap -n -p 22 " + strFrom + "-" + \
                    str(lstTo[3]) + " | grep '" + \
                    str(lstFrom[0]) + "\\|ssh\\|MAC'"
        elif nPlatform == 1:
            if myConfig.Home:
                strNmap = "nmap -n -sT -T4 -p 22 " + strFrom + "-" + str(lstTo[3]) + \
                    " | Select-String -pattern '" + str(lstFrom[0]) + "|ssh'"
            else:
                strNmap = "nmap -n -sT -T4 -p 22 " + strFrom + "-" + str(lstTo[3]) + \
                    " | Select-String -pattern '" + \
                    str(lstFrom[0]) + "|ssh|MAC'"
        if strNmap.find("sudo") >= 0:
            logger.info(
                "Please check if you may need to enter the password of sudo command in the console or terminal")
        logger.info("==== " + strNmap)

        # Run nmap and check how long nmap takes
        t0 = datetime.now()
        if nPlatform == 2 or nPlatform == 3:
            results = subprocess.Popen(
                strNmap, stdout=subprocess.PIPE, shell=True).communicate()[0].split(b"\n")
        else:
            results = subprocess.Popen(
                ["powershell", "-Command", strNmap], stdout=subprocess.PIPE).stdout
        t1 = datetime.now()
        diff = t1 - t0
        logger.info("== Scan from " + strFrom +
                    "-" + strTo + " for port=22 takes %4.2f seconds", diff.total_seconds())

        # Initial index j to 0 for 1st selection scan only
        # if i == 0:
        #    j = 0
        # ❯ nmap -n -sT -p 22 172.17.20.3-30 | grep '172\|ssh'
        # Nmap scan report for 172.17.20.4
        # 22/tcp open  ssh
        # Nmap scan report for 172.17.20.5
        # 22/tcp open  ssh
        # ...etc.
        for bResult in results:
            strTmps = bResult.decode("utf-8").split(" ")
            # 1st line include IPv4. Get IPv4.
            if len(strTmps) > 8 and strTmps[7] == "recognized" and nPlatform == 1:
                logger.warning(bResult)
                logger.warning(
                    "Please check the nmap installed or the $Env:path include path of namp of Windows and quit the program.")
                quit()
            if strTmps[0] == "Nmap" and strTmps[1] == "scan":
                if len(strTmps[4]) > 10:  # Length of IPv4 shall great than 10 digits
                    if nPlatform == 2 or nPlatform == 3:
                        strIP = strTmps[4]
                    else:
                        strIP = strTmps[4][:-2]  # trim "\n\r" for Windows OS
                    logger.debug(
                        "Get the IP %s from the nmap scan result", strIP)
            if strTmps[0] == "22/tcp":  # 2nd line include ssh port 22 is 'open' or 'close'
                if strTmps[1] == "open":
                    nSsh = 1
                else:
                    nSsh = 0
                # only take care of the worker when it's ssh/22 is "open".
                logger.debug(
                    "The port 22/ssh of the IP %s is '%s'", strIP, strTmps[1])
                if nSsh == 1:
                    workerArray.append(worker())
                    workerArray[j].Number = j
                    workerArray[j].IP = strIP
                    dictIPtoIndex[strIP] = j
                    workerArray[j].Ssh = nSsh
                    j += 1
                if myConfig.Home:
                    logger.debug(
                        "myConfig.Home=%d, Force to scan this worker no matter the MAC is found or not.", myConfig.Home)
                    if j >= 1 and nSsh == 1:
                        workerArray[j-1].bPowerRay = True
                        nCount += 1
            if strTmps[0] == "MAC":  # it's a MAC address
                if nPlatform == 1:
                    logger.debug("Nmap scan result '%s'",
                                 bResult.decode("utf-8")[:-2])  # Windows remove "\r\n"
                else:
                    logger.debug("Nmap scan result '%s'",
                                 bResult.decode("utf-8"))

                if strTmps[2][0:8] in {"68:5E:6B", "F4:3E:66"}:
                    logger.debug(
                        "Only check the MAC(%s) OUI (The irst 6-digits of '%s') belong to (PowerRay) or '%s' (Bee Computing)", strTmps[2], "68:5E:6B", "F4:3E:66")
                    if nSsh == 1 and j >= 1:
                        workerArray[j-1].bPowerRay = True
                        nCount += 1
                else:
                    logger.warning(
                        "The MAC OUI (The first 6-digits of '%s') doesn't belong to '%s' (PowerRay) or '%s' (Bee Computing). Skit it.", strTmps[2], "68:5E:6B", "F4:3E:66")
                    if j >= 1:
                        workerArray[j-1].MAC = strTmps[2]
                        workerArray[j-1].bPowerRay = False
                        workerArray[j-1].FailCode = 2
                        workerArray[j-1].FailDesc = \
                            "The MAC OUI (" + \
                            strTmps[2][0:8] + ") is not valid"
                        if myConfig.Home:  # if myConfig.Home != 0 to ignore MAC address OUI checking
                            logger.info(
                                "myConfig.Home = %d != 0 to ignore MAC OUI checking", myConfig.Home)
                            if nSsh == 1 and j >= 1:
                                workerArray[j-1].bPowerRay = True
                                nCount += 1
                        workerArray[j-1].Ssh = 1

        action.scan = False  # finish the scan for all IPs
        logger.info(
            "====== Finish IP & port=22 scan and set action.scan to False and please wait for brower launch for a moment")

    # Start to gather information of each worker when it's ssh/22 is "open"
    logger.info(
        "====== Star to collect valid worker's information")
    for i in range(len(workerArray)):
        if nCount == 0:
            logger.info("No worker found.")
            return
        if action.scan:  # 111111g1242
            return
        # ssh to worker's IP. username=root, no password
        myIP = workerArray[i].IP
        workerArray[i].datetime = datetime.now()
        if bLevelname:
            logger.handlers[0].setFormatter(logging.Formatter(strLogFormater2))
        if FHLog != None:
            FHLog.setFormatter(logging.Formatter(strLogFormater2))
        if i == 0:
            logger.warning("==== Start to scan all availiable IPs")
        logger.warning("== Scan " + myIP)
        if bLevelname:
            logger.handlers[0].setFormatter(logging.Formatter(strLogFormater1))
        if FHLog != None:
            FHLog.setFormatter(logging.Formatter(strLogFormater1))
        client, strReturn = sshToWoker(myIP)
        if client == None:
            workerArray[i].FailDesc = "Can not ssh to " + myIP
            workerArray[i].FailCode = 2
            continue

        bCreateFolder = True
        # Create /root/scripts/ch and copy all scripts from local to worker. And change the *.sh to executable
        if bCreateFolder:
            stdin, stdout, stderr = client.exec_command(
                "rm -rf " + strScriptsPath + "; mkdir -p " + strScriptsPath)
            logger.info(
                "Delete %s and re-created on the worker.", strScriptsPath)
            stdout.close()
            stderr.close()
            # scp all scripts and python files to worker
            if nPlatform == 1:  # Windows 10/11 or Server
                # Create a PowerShell scrip file go.ps1
                # C:
                # cd $HOME\ch
                # ..\AppData\Local\Programs\Python\Python310\python.exe $HOME\ch\PowerRayETC.[ver].py
                bSshFailed = False
                a = "\\"
                filename = "C:\\Users\\" + os.getlogin() + a + "ch\\scripts\\ch"
                logger.info(
                    "Copy all the scripts from folder '%s'", str(filename))
                cmd1 = "scp -p -C -r -4 " + str(filename) + " root@" + \
                    workerArray[i].IP + ":/root/scripts"
                cmd2 = "chmod +x " + strScriptsPath + "*.sh"
                cmd3 = r"ssh-keygen.exe -R " + strIP  # + " 2>&1 | Out-Null"
                ret = subprocess.run(cmd1, shell=True, stdout=subprocess.PIPE,
                                     stdin=subprocess.PIPE, stderr=subprocess.PIPE)
                if ret.returncode == 0:
                    logger.info(
                        "Run '%s' on Windows. The return = %d (OK=0 NG>0)", cmd1, ret.returncode)
                else:
                    logger.warning(
                        "Run '%s' on Windows. The return = %d (OK=0 NG>0)", cmd1, ret.returncode)
                lines = ret.stdout.decode("utf-8")
                errlines = ret.stderr.decode("utf-8")
                stderr.close()
                stdout.close()
                logger.info("len of stdout=%d, stderr=%d",
                            len(lines), len(errlines))
                if len(lines) > 0:
                    logger.info(lines[0:-1])
                if len(errlines) > 0:
                    strTmps = errlines.split("\r\n")
                    for strTmp in strTmps:
                        if len(strTmp) > 0 and strTmp[-1] == "\n":  # v1.03
                            strTmp = strTmp[0:-1]
                        if len(strTmp) > 0:
                            if len(errlines) >= 100:
                                if strTmp.find("fingerprint") >= 0:
                                    bSshFailed = True
                                    strTemps = strTmp.split("\n")
                                    if len(strTemps) == 2:
                                        logger.warning(
                                            strTemps[0] + " " + strTemps[1])
                                    else:
                                        for strTemp in strTemps:
                                            logger.warning(strTemp)
                    if bSshFailed:
                        logger.warning(
                            "Known host is conflict. Run '%s' to remove it from local known hosts.", cmd3)
                        ret = subprocess.run(cmd3, shell=True, stdout=subprocess.PIPE,
                                             stdin=subprocess.PIPE, stderr=subprocess.PIPE)
                        if ret.returncode == 0:
                            logger.info(
                                "Run '%s' on Windows. The return = %d (OK=0 NG>0)", cmd3, ret.returncode)

                            # Re-run scp again
                            ret1 = subprocess.run(cmd1, shell=True, stdout=subprocess.PIPE,
                                                  stdin=subprocess.PIPE, stderr=subprocess.PIPE)
                            if ret1.returncod == 0:
                                lines = ret1.stdout.decode("utf-8")
                                errlines = ret1.stderr.decode("utf-8")
                                stderr.close()
                                stdout.close()
                                logger.info("len of stdout=%d, stderr=%d",
                                            len(lines), len(errlines))
                                if len(lines) > 0:
                                    logger.info(lines[0:-1])
                                if len(errlines) > 0:
                                    if errlines.find("Permanently added") < 0:
                                        workerArray[i].FailCode = 2
                                        workerArray[i].FailDesc = "Can not copy scripts to worker"
                                        continue
                            else:
                                errlines = ret1.stderr.decode("utf-8")
                                logger.error(errlines)
                                workerArray[i].FailCode = 99
                                workerArray[i].FailDesc = "Unknow Error"
                                continue
                        else:
                            logger.warning(
                                "Run '%s' on Windows. The return = %d (OK=0 NG>0)", cmd3, ret.returncode)
                            workerArray[i].FailCode = 2
                            workerArray[i].FailDesc = "Can not remove key from known hosts"
                            continue

                stdin, stdout, stderr = client.exec_command(cmd2)
                lines = stdout.readlines()
                errlines = stderr.readlines()
                stdout.close()
                stderr.close()
                if len(lines) > 0:
                    for line in lines:
                        logger.info(line)
                if len(errlines) == 0:
                    logger.info("Run '%s' successfully", cmd2)
                else:
                    for line in errlines:
                        logger.error(line)
                    logger.error("Run '%' failed", cmd2)
                    workerArray[i].FailCode = 6
                    workerArray[i].FailDesc = "chmod +x failed"
                    continue
            else:
                cmd1 = "scp ./scripts/ch/*.* root@" + \
                    workerArray[i].IP + ":" + \
                    strScriptsPath + ". > /dev/null 2>&1"
                logger.info(
                    "Run '%s' on local Linux like OS.", cmd1)
                ret = os.system(cmd1)
                logger.info("Run '%s' return %d", cmd1, ret)
                cmd2 = "chmod +x " + strScriptsPath + "*.sh"
                logger.info("Run '%s' on remote worker.", cmd2)
                stdin, stdout, stderr = client.exec_command(cmd2)
                lines = stdout.readlines()
                errlines = stderr.readlines()
                stdout.close()
                stderr.close()
                if len(lines) > 0:
                    for line in lines:
                        logger.info(line)
                if len(errlines) == 0:
                    logger.info("Run '%s' successfully", cmd2)
                else:
                    for line in errlines:
                        logger.error(line)
                    logger.error("Run '%' failed", cmd2)

        # Get worker's MAC address of br-lan and worker's name
        cmd = strScriptsPath + "getMACnWorker.sh 14400"
        stdin, stdout, stderr = client.exec_command(cmd)
        logger.info("Run '%s' on worker.", cmd)
        errLines = stderr.readlines()
        if len(errLines) > 0 and errLines[0].find("Permission"):
            workerArray[i].MAC = "NA"
            workerArray[i].Worker = "NA"
            logger.warning(
                "getMACnWorker.sh permission denied. Set MAC and Worker as 'NA'")
        else:
            lines = stdout.readlines()
            workerArray[i].MAC = lines[0].rstrip()
            if lines[1].rstrip() == "IOSCAN":
                workerArray[i].Worker = ""
            else:
                workerArray[i].Worker = lines[1].rstrip()
            logger.info("getMACnWorker.sh return MAC=%s and Worker='%s'",
                        workerArray[i].MAC, workerArray[i].Worker)
            if lines[1].rstrip() == "IOSCAN" and lines[2].rstrip() == "4hr":
                workerArray[i].FailCode = 1
                workerArray[i].FailDesc = "More than 4 hours still in IOSCAN state"
        stderr.close()
        stdout.close()

        # if /root/Model is not exist. Query the MS-SQL DB and write Model and ServerID to /root
        cmd = "ls /root/Model"
        stdin, stdout, stderr = client.exec_command(cmd)
        lines = stderr.readlines()
        stderr.close()

        bException = False
        nMSSQL = 0
        if len(lines) > 0 and lines[0].find("No such file or directory") != -1:
            logger.warning(
                "Run  %s and return 'No such file or directory' then querty MS-SQL and wrtie to /root/Model and /root/ServerID", cmd)
            # Querty MS-SQL and wrtie to /root/Model amd /root/ServerID (only for production site)
            # Connect to database
            conn = None
            cursor = None
            try:
                # server = '192.168.1.5'
                # database = 'Darwin_SB'
                # username = 'test123'
                # password = 'test'
                server = myConfig.mssqlHost
                database = myConfig.mssqlDatabase
                username = myConfig.mssqlUser
                password = myConfig.mssqlPassword
                conn = pymssql.connect(server=server, user=username,
                                       password=password, database=database)
                nMSSQL = 1
                if conn:
                    logger.info(
                        "Connect to MS-SQL production database successfully")
                    cursor = conn.cursor()
                    strModel = 'NA'
                    strServerID = 'NA'
                    if cursor:
                        strMAC = workerArray[i].MAC
                        cmd = "exec " + myConfig.mssqlStoreProcedure + "'"+strMAC+"';"
                        cursor.execute(cmd)
                        logger.info(
                            "Run MS-SQL stored procedure '%s'", cmd)
                        row = cursor.fetchall()
                        if row and len(row[0]) == 2:
                            if row[0][0] is None:
                                logger.warning("IP=%s has no ServerID in MS-SQL",
                                               workerArray[i].IP)
                            else:
                                strServerID = row[0][0]
                                logger.info(
                                    "The ServerID=%s from MS-SQL Stored Procedure", strServerID)
                            if row[0][1] is None:
                                logger.warning("IP=%s has no strModel in MS-SQL",
                                               workerArray[i].IP)
                            else:
                                strModel = row[0][1]
                                logger.info(
                                    "The Model=%s from MS-SQL Stored Procedure", strModel)
                            workerArray[i].ServerID = strServerID
                            workerArray[i].Model = strModel
                            cmd = "echo " + strServerID + " > /root/ServerID; echo " + strModel + " > /root/Model"
                            stdin, stdout, stderr = client.exec_command(cmd)
                            logger.info(
                                "echo ServerID & Model in worker's /root directory")
            except Exception as e:
                print(e)
                pass

        # Get Model from /root/Model
        cmd = strScriptsPath + "getModel.sh"
        stdin, stdout, stderr = client.exec_command(cmd)
        lines = stdout.readlines()
        if len(lines) > 0 and lines[0].find("No such file or directory") != -1:
            logger.warning(
                "Run '%s' and can't find /root/Model. Set /root/Model as 'NA'")
            workerArray[i].Model = 'NA'
        elif len(lines) > 0:
            strModel = lines[0][:-1]
            logger.info("Model=%s", strModel)
            workerArray[i].Model = strModel
        else:
            logger.warning(
                "Unknown reason can't get /root/Model. echo 'NA' > /root/Model")
            workerArray[i].Model = 'NA'
        stdout.close()

        # Get ServerID from /root/ServerID
        strServerID = ''
        strModel = ''
        stdin, stdout, stderr = client.exec_command(
            strScriptsPath + "getServerID.sh")
        lines = stdout.readlines()
        if len(lines) > 0 and lines[0].find("No such file or directory") != -1:
            logger.warning(
                "Can't find /root/ServerID. echo 'NA' > /root/ServerID")
            workerArray[i].ServerID = 'NA'
        elif len(lines) > 0:
            strServerID = lines[0][:-1]
            workerArray[i].ServerID = strServerID
        else:
            workerArray[i].ServerID = 'NA'
        stdout.close()

        logger.info("IP=%s, Worker=%s, MAC=%s, Model=%s, ServerID=%s",
                    workerArray[i].IP, workerArray[i].Worker, workerArray[i].MAC, strModel, strServerID)

        def getRemoteScript(client, scriptfile):
            strReturn = ''
            strFailDesc = ''
            cmd = strScriptsPath + scriptfile
            logger.info("run remote command=%s", cmd)
            stdin, stdout, stderr = client.exec_command(cmd)
            lines = stdout.readlines()
            errlines = stderr.readlines()
            stderr.close()
            stdout.close()
            logger.info("len of stdout=%d, stderr=%d",
                        len(lines), len(errlines))
            bPMBus = False
            for line in errlines:
                if line.find("PMBus.py") >= 0:
                    bPMBus = True
                if line.find("OSError: [Errno 71]") >= 0:
                    logger.error(line.strip())
                # "Build Version=20221101-001" too add this line to get the latest line of errlines
                if line.find("I2C_SMBUS") >= 0:
                    strFailDesc = line.strip()
                    # "Build Version=20221101-001" too add this line to get the latest line of errlines
                    logger.error(strFailDesc)
            if bPMBus:
                logger.error(  # "Build Version=20221031-002" change from info to error
                    "python3 /root/scripts/ch/PMBus.py and could be I2C_SMBUS issue")
            for line in lines:
                if line[0] == "'":
                    logger.info(scriptfile + " -> " + line[1:-2])
                else:
                    logger.info(scriptfile + " -> " + line[:-1])
            if len(lines) >= 1:
                if lines[0][0] == "'":
                    strReturn = lines[0][1:-2]
                else:
                    strReturn = lines[0][0:-1]
            logger.info("strReturn=%s", strReturn)
            if strReturn == '':
                strReturn = 'NA'
            logger.info("return %s", strReturn)
            return strReturn, strFailDesc

        # Get pool address from /etc/config/cgminer
        strTmp, strFailDesc = getRemoteScript(client, "getPoolAddress.sh")
        workerArray[i].PoolAddress = strTmp

        # Get Wallet address from /etc/config/cgminer
        strTmp, strFailDesc = getRemoteScript(client, "getWalletAddress.sh")
        workerArray[i].WalletAddress = strTmp

        workerArray[i].Account = 'NA'  # No account for ETC

        # Get password from /etc/config/cgminer
        strTmp, strFailDesc = getRemoteScript(client, "getPassword.sh")
        workerArray[i].Password = strTmp

        # Get Miner OP Freq from /etc/config/cgminer
        strTmp, strFailDesc = getRemoteScript(client, "getMinerOPFreq.sh")
        workerArray[i].MinerOPFreq = strTmp

        # Get hostname from /etc/config/system
        strTmp, strFailDesc = getRemoteScript(client, "getHostname.sh")
        workerArray[i].Hostname = strTmp

        # Get miner's status from different combination of situations
        cmd = strScriptsPath + "getStatus.sh 300"
        if workerArray[i].FailCode == 0:
            workerArray[i].FailDesc = ''
        logger.info("run remote command=%s", cmd)
        stdin, stdout, stderr = client.exec_command(cmd)
        lines = stdout.readlines()
        errlines = stderr.readlines()
        stderr.close()
        stdout.close()
        logger.info("len of stdout=%d, stderr=%d",
                    len(lines), len(errlines))
        for line in lines:
            logger.debug(line.rstrip())
        for line in errlines:
            logger.error(line.rstrip())
        strStatus = "Unknown"
        logger.debug("set strStatus = %s", strStatus)
        if len(lines) >= 1:
            strStatus = lines[0].rstrip()
            logger.debug("strStatus = %s", strStatus)
            # Only for "FailCode,3,IOSCAN and Mining are both in the same time"
            if strStatus[0:8] == "FailCode":
                logger.error(strStatus)
                strTmps = strStatus.split(',')
                strStatus = "Fail"
                workerArray[i].Status = strStatus
                workerArray[i].FailCode = strTmps[1]
                workerArray[i].FailDesc = strTmps[2]
                if len(lines) >= 2:
                    strStatus = lines[1][:-1]
                    if strStatus == "IOSCAN":
                        logger.info("strStatus=%s", strStatus)
            elif strStatus[0:6] == "IOSCAN":
                strStatus = "IOSCAN"
        workerArray[i].Status = strStatus

        if strStatus == "DAG":
            for line in lines:
                line = line[:-1]
                if (line != "DAG"):
                    strProgress = line[:-1]
                    pos1 = strProgress.find("/")
                    if pos1 != -1:
                        strP1 = strProgress[pos1-3:pos1]  # 前面為、二位數，或三位數
                        if strP1[0] == 'y':
                            strP1 = strProgress[pos1-1:pos1]  # 前面為一位數
                        strP2 = strProgress[pos1+1:pos1+5]
                        nP1 = int(strP1)
                        nP2 = int(strP2)
                        fPercent = float(nP1/nP2)*100
                        strTemp = str(fPercent)
                        pos2 = strTemp.find(".")
                        if pos2 != -1:
                            strPercent = strTemp[0:pos2+3] + "%"
                            workerArray[i].Progress.append(strPercent)
        elif strStatus == "IOSCAN":
            for line in lines:
                line = line[:-1]
                if line[0:8] == "FailCode":
                    continue
                if (line != "IOSCAN"):
                    nP1 = int(line)
                    nP2 = 1152*8
                    fPercent = float(nP1/nP2)*100
                    strTemp = str(fPercent)
                    pos2 = strTemp.find(".")
                    if pos2 != -1:
                        strPercent = strTemp[0:pos2+3] + "%"
                        workerArray[i].Progress.append(strPercent)
        for j in range(8-len(workerArray[i].Progress)):
            workerArray[i].Progress.append('NA')
        stdout.close()

        ''' Test Purpose
        strTime, strHashRateMs = myEthermineApi.getWorkerCurrentStats(workerArray[i].WalletAddress, strWorker="192-168-66-139")
        if strTime == '':
            for j in range(len(myConfig.URL)):
                if workerArray[i].WalletAddress.find(myConfig.URL[j]) >= 0:
                    if j == 0:
                        strWalletAddress = myConfig.URL[1]
                    else:
                        strWalletAddress = myConfig.URL[0]
            strTime, strHashRateMs = myEthermineApi.getWorkerCurrentStats(strWalletAddress, strWorker="192-168-66-139")
        '''

        if strStatus in {"Mining"}:
            if workerArray[i].Worker != '':
                strTime, strHashRateMs = myEthermineApi.getWorkerCurrentStats(
                    workerArray[i].WalletAddress, strIP=workerArray[i].IP, strWorker=workerArray[i].Worker)
                logger.info("return time=%s, HashRate=%s M/s",
                                 strTime, strHashRateMs)
            if strTime == '':
                for j in range(len(myConfig.URL)):
                    if workerArray[i].WalletAddress.find(myConfig.URL[j]) >= 0:
                        if j == 0:
                            strWalletAddress = myConfig.URL[1]
                        else:
                            strWalletAddress = myConfig.URL[0]
                strTime, strHashRateMs = myEthermineApi.getWorkerCurrentStats(
                    strWalletAddress, strIP=workerArray[i].IP, strWorker=workerArray[i].Worker)
                logger.info("return time=%s, HashRate=%s M/s",
                                 strTime, strHashRateMs)
            #workerArray[i].datetime = datetime.now()
            workerArray[i].PoolHashRate = strHashRateMs
        else:
            #workerArray[i].datetime = datetime.now()
            workerArray[i].PoolHashRate = 0

        # Get board temperatures from "python3 /root/ft930_control/FT930_control.py". PR_8X, PR_1U and PR_SB has different number of board temperatures
        cmd = strScriptsPath + "getBoardTemp.sh"
        stdin, stdout, stderr = client.exec_command(cmd)
        lines = stdout.readlines()
        errlines = stderr.readlines()
        for line in errlines:
            logger.info(line[:-1])
        for line in lines:
            line = line[:-1]
            workerArray[i].Temperature.append(line)
        for j in range(8-len(workerArray[i].Temperature)):
            workerArray[i].Temperature.append('NA')
        stderr.close()
        stdout.close()

        # Install smbus2 if not installed
        transport = client.get_transport()
        transport.set_keepalive(60)
        bSmbus2 = False
        cmd = "python3 " + strScriptsPath + "test_smb2.py"
        stdin, stdout, stderr = client.exec_command(cmd)
        errLines = stderr.readlines()
        for line in errLines:
            if line[:-1].find("No module named 'smbus2'") >= 0:
                bSmbus2 = True
                logger.warning(
                    "No module named 'smbus2' on IP=%s", workerArray[i].IP)
        stderr.close()

        if bSmbus2:
            # cmd = "pip3 install --trusted-host pypi.org smbus2"
            cmd = "python3 -m pip install --trusted-host files.pythonhosted.org --trusted-host pypi.org --trusted-host pypi.python.org smbus2"
            logger.info("Install smbus2 via '%s'", cmd)
            stdin, stdout, stderr = client.exec_command(cmd)
            lines = stdout.readlines()
            for line in lines:
                logger.info(line[:-1])
            errlines = stderr.readlines()
            for line in errlines:
                logger.warning(line[:-1])
            stdout.close()
            stderr.close()

        # Get FAN speed from ~/scripts/ch/getFanSpeed.sh
        nFanSpeed = 0
        strFailDesc = ''
        cmd = strScriptsPath + "getFanSpeed.sh 2>/dev/null"
        logger.info("Before run '%s'", cmd)
        try:
            stdin, stdout, stderr = client.exec_command(cmd)
            logger.info("After run '%s'", cmd)
            errlines = stderr.readlines()
            lines = stdout.readlines()
            stderr.close()
            stdout.close()
            logger.info("len of stdout=%d, stderr=%d",
                        len(lines), len(errlines))
            # "Build Version=20221101-001" too add this line to get the latest line of errlines
            bPMBus = False
            for line in errlines:
                if line.find("PMBus.py") >= 0:
                    bPMBus = True
                if line.find("OSError: [Errno 71]") >= 0:
                    logger.error(line.strip())
                if line.find("I2C_SMBUS") >= 0:
                    strFailDesc = line.strip()
                    logger.error(strFailDesc)
                if bPMBus:
                    logger.error(  # "Build Version=20221031-002" change from info to error
                        "python3 /root/scripts/ch/PMBus.py and could be I2C_SMBUS issue")
            for line in lines:
                logger.info("'" + line[:-1] + "'")
                strTmp = line[:-1]
                if strTmp == 'Initializing PMBUS... ':
                    workerArray[i].FanSpeed.append('NA')
                    nFanSpeed += 1
                    break
                else:
                    nPos = strTmp.find('.')
                    line = line[0:nPos]
                    workerArray[i].FanSpeed.append(line)
                nFanSpeed += 1
        except Exception as e:
            logger.error(e)
        if nFanSpeed < 5:
            for j in range(nFanSpeed, 5):
                workerArray[i].FanSpeed.append("NA")
                logger.info("append('NA') for %d", j)
        if strFailDesc.find("I2C_SMBUS") >= 0:
            workerArray[i].FailCode = 7
            workerArray[i].FailDesc = strFailDesc

        # Get power from ~/scripts/ch/getPower.sh
        strTmp, strFailDesc = getRemoteScript(client, "getPower.sh")
        if strTmp == '':
            strTmp = 'NA'
        workerArray[i].PowerConsumption = strTmp
        if strFailDesc.find("I2C_SMBUS") >= 0:
            workerArray[i].FailCode = 7
            workerArray[i].FailDesc = strFailDesc

        # Get WorkingAsic from /root/log/messages or /tmp/log/messages for different control board
        if (workerArray[i].Hostname == "RTD1619B"):
            stdin, stdout, stderr = client.exec_command(
                "tail -500 /root/log/messages | grep 'SOLUTION FOUND' | awk '{print $12 $15}'")
        else:
            stdin, stdout, stderr = client.exec_command(
                "tail -500 /tmp/log/messages | grep 'SOLUTION FOUND' | awk '{print $12 $15}'")
        lines = stdout.readlines()
        for line in lines:
            line = line[:-2]
            nHashboard = int(line[2]) - 1
            nAsic = int(line[0])
            workerArray[i].HashboardAsic[nHashboard][nAsic] = 1
        for ii in range(4):
            for jj in range(2):
                if workerArray[i].HashboardAsic[ii][jj]:
                    workerArray[i].WorkingAsic += 1
        time.sleep(1)
        stdout.close()
        client.close()

############################################################################################################################################################################
# "Build Version=20221103-001"
    '''
    if bLevelname:
        logger.handlers[0].setFormatter(logging.Formatter(strLogFormater2))
    if FHLog != None:
        FHLog.setFormatter(logging.Formatter(strLogFormater2))
    logger.info("======== Start webdriver parsing")
    if bLevelname:
        logger.handlers[0].setFormatter(logging.Formatter(strLogFormater1))
    if FHLog != None:
        FHLog.setFormatter(logging.Formatter(strLogFormater1))
    try:
        # Get CurrentHashrate from pool web site via WebDriver.
        # Important: the WebDriver shall be the same version as the web browser
        # nWebDriver = args.webdriver
        options = Options()
        options.use_chromium = True
        options.headless = True
        # options.add_argument(r"headless")
        options.add_argument(r"disable-gpu")
        if nWebdriver == 1:
            driver = webdriver.Edge(service=s, options=options)
        elif nWebdriver == 2:
            driver = webdriver.Edge(service=s, options=options)
        # "https://etc.ethermine.org/miners/20c0ac4e73ed4db87fef692991c0f4becff93cbc/dashboard")
        # "https://etc.ethermine.org/miners/57fc699ad1249f65759e1af273e26350dece1eb6/dashboard")

        if bLevelname:
            logger.handlers[0].setFormatter(logging.Formatter(strLogFormater2))
        if FHLog != None:
            FHLog.setFormatter(logging.Formatter(strLogFormater2))
        logger.warning(
            "==== Launch the browser to parse the worker's CurrentHashrate")
        for walletAddress in myConfig.URL:
            strURL = "https://etc.ethermine.org/miners/" + walletAddress + "/dashboard"
            logger.warning("== Launch '%s'", strURL)
            if bLevelname:
                logger.handlers[0].setFormatter(
                    logging.Formatter(strLogFormater1))
            if FHLog != None:
                FHLog.setFormatter(logging.Formatter(strLogFormater1))
            driver.get(strURL)
            driver.implicitly_wait(60)
            driver.minimize_window()

            elements = driver.find_elements(By.CLASS_NAME, 'table-body')

            for element in elements:
                x = element.get_attribute('innerHTML')
                if myConfig.Verbose >= 6:
                    logger.info("innerHTML=%s", str(x))
                soup = BeautifulSoup(x, "html.parser")
                if myConfig.Verbose >= 5:
                    logger.info("soup=%s", str(soup))
                rows = soup.find_all("td", class_="string")
                if myConfig.Verbose >= 4:
                    logger.info("rows=%s", str(rows))
                for row in rows:
                    if myConfig.Verbose >= 3:
                        logger.info("row=%s", str(row))
                    if len(row.attrs) == 4:  # Name
                        strIP = row.text.replace("-", ".")

                rows = soup.find_all("td", class_="number")
                if myConfig.Verbose >= 4:
                    logger.info("rows=%s", str(rows))
                for row in rows:
                    if myConfig.Verbose >= 3:
                        logger.info("row=%s", str(row))
                    if row.attrs['data-label'] == "Current Hashrate":
                        if myConfig.Verbose >= 2:
                            logger.info(
                                "row.attrs['data-label']=%s", row.attrs['data-label'])
                        fCurrentHashrate = 0.0
                        if row.text != '0':
                            if myConfig.Verbose >= 2:
                                logger.info(
                                    "row.text=%s, row.attrs['unit']=%s", row.text, row.attrs['unit'])
                            if row.attrs['unit'] == "GH/s":
                                fCurrentHashrate = float(row.text)*1000
                                if myConfig.Verbose >= 2:
                                    logger.info("IP=%s, unit=%s, unit=%s -> %7.1f M/s",
                                                strIP, row.text, row.attrs['unit'], fCurrentHashrate)
                            else:
                                fCurrentHashrate = float(row.text)
                                if myConfig.Verbose >= 2:
                                    logger.info(
                                        "IP=%s, unit = None -> current Hashrate = %7.1f M/s", strIP, fCurrentHashrate)

                strTestIP = strIP
                fTestCurrentHashrate = fCurrentHashrate
                if strIP in dictIPtoIndex:
                    workerArray[dictIPtoIndex[strIP]
                                ].PoolHashRate = fCurrentHashrate
                    workerArray[dictIPtoIndex[strIP]].Web = 1
                    logger.info(
                        "IP=%s current Hashrate = %10.3f M/s", strIP, fCurrentHashrate)
        driver.quit()
        logger.info("Close the browser")
    except Exception as e:
        logger.error('webdriver.Exception = ', e)
    '''
############################################################################################################################################################################

    n0 = 0
    # workerArray.clear()
    # dictIPtoIndex.clear()  # dictionary mapping IP to index in workerArray
    # clear the tvWorker treeview before start to insert the row data
    tvWorker.delete(*tvWorker.get_children())
    logger.info("Insert Worker's informatin into table SCAN")
    # try:
    n0 = 1
    conn = ConnectToDB()
    n0 = 2
    cursor = GetCursorDB(conn)
    n0 = 3
    batch = GetBatchID(cursor)
    n0 = 4

    # Insert information of each worker into tktree when it's ssh/22 is "open"
    nWritten = 0
    n1 = 0
    for i in range(len(workerArray)):
        if workerArray[i].bPowerRay:
            if workerArray[i].PoolHashRate == None:
                workerArray[i].PoolHashRate = 0
            w = workerArray[i]
            n1 = 0
            try:
                n1 = 1
                myTag = "normal"
                if not (w.Worker == None or w.Worker == ""):
                    if not w.Status == "offline":
                        strWorker = w.Worker
                        if validate(strWorker.replace("-", ".")) and not strWorker.replace("-", ".") == w.IP:
                            myTag = "red"
                n1 = 2
                w.Model = "" if w.Model == None else w.Model
                w.IP = "" if w.IP == None else w.IP
                w.Worker = "" if w.Worker == None else w.Worker
                w.MAC = "" if w.MAC == None else w.MAC
                w.ServerID = "" if w.ServerID == None else w.ServerID
                w.Status = "" if w.Status == None else w.Status
                if len(w.Progress) < 8:
                    for j in range(8-len(w.Progress)):
                        w.Progress.append("NA")
                w.Progress[0] = "" if w.Progress[0] == None else w.Progress[0]
                w.Progress[1] = "" if w.Progress[1] == None else w.Progress[1]
                w.Progress[2] = "" if w.Progress[2] == None else w.Progress[2]
                w.Progress[3] = "" if w.Progress[3] == None else w.Progress[3]
                w.Progress[4] = "" if w.Progress[4] == None else w.Progress[4]
                w.Progress[5] = "" if w.Progress[5] == None else w.Progress[5]
                w.Progress[6] = "" if w.Progress[6] == None else w.Progress[6]
                w.Progress[7] = "" if w.Progress[7] == None else w.Progress[7]
                w.PoolHashRate = "" if str(
                    w.PoolHashRate) == None else str(w.PoolHashRate)
                w.SelfCalHashRate = "" if w.SelfCalHashRate == None else w.SelfCalHashRate
                w.WorkingAsic = "" if str(
                    w.WorkingAsic) == None else str(w.WorkingAsic)
                if len(w.FanSpeed) < 5:
                    for j in range(5-len(w.FanSpeed)):
                        w.FanSpeed.append("NA")
                w.FanSpeed[0] = "" if w.FanSpeed[0] == None else w.FanSpeed[0]
                w.FanSpeed[1] = "" if w.FanSpeed[1] == None else w.FanSpeed[1]
                w.FanSpeed[2] = "" if w.FanSpeed[2] == None else w.FanSpeed[2]
                w.FanSpeed[3] = "" if w.FanSpeed[3] == None else w.FanSpeed[3]
                w.FanSpeed[4] = "" if w.FanSpeed[4] == None else w.FanSpeed[4]
                w.PoolAddress = "" if w.PoolAddress == None else w.PoolAddress
                w.WalletAddress = "" if w.WalletAddress == None else w.WalletAddress
                w.Account = "" if w.Account == None else w.Account
                w.Password = "" if w.Password == None else w.Password
                w.MinerOPFreq = "" if w.MinerOPFreq == None else w.MinerOPFreq
                w.PowerConsumption = "" if w.PowerConsumption == None else w.PowerConsumption
                w.DHCPorFixedIP = "" if w.DHCPorFixedIP == None else w.DHCPorFixedIP
                if len(w.Temperature) < 8:
                    for j in range(8-len(w.Temperature)):
                        w.Temperature.append("NA")
                w.Temperature[0] = "" if w.Temperature[0] == None else w.Temperature[0]
                w.Temperature[1] = "" if w.Temperature[1] == None else w.Temperature[1]
                w.Temperature[2] = "" if w.Temperature[2] == None else w.Temperature[2]
                w.Temperature[3] = "" if w.Temperature[3] == None else w.Temperature[3]
                w.Temperature[4] = "" if w.Temperature[4] == None else w.Temperature[4]
                w.Temperature[5] = "" if w.Temperature[5] == None else w.Temperature[5]
                w.Temperature[6] = "" if w.Temperature[6] == None else w.Temperature[6]
                w.Temperature[7] = "" if w.Temperature[7] == None else w.Temperature[7]
                w.FailDesc = "" if w.FailDesc == None else w.FailDesc

                if myConfig.Verbose >= 2:
                    logger.debug("w.Model=%s, w.IP=%s, w.Worker=%s, w.MAC=%s, w.ServerID=%s, w.Status=%s, w.Progress[0]=%s, w.Progress[1]=%s, w.Progress[2]=%s, w.Progress[3]=%s, w.Progress[4]=%s, w.Progress[5]=%s, w.Progress[6]=%s, w.Progress[7]=%s, w.PoolHashRate=%s, w.SelfCalHashRate=%s, w.WorkingAsic=%s, w.FanSpeed[0]=%s, w.FanSpeed[1]=%s, w.FanSpeed[2]=%s, w.FanSpeed[3]=%s, w.FanSpeed[4]=%s, w.PoolAddress=%s, w.WalletAddress=%s, w.Account=%s, w.Password=%s, w.MinerOPFreq=%s, w.PowerConsumption=%s, 'NA'=%s, w.Temperature[0]=%s, w.Temperature[1]=%s, w.Temperature[2]=%s, w.Temperature[3]=%s, w.Temperature[4]=%s, w.Temperature[5]=%s, w.Temperature[6]=%s, w.Temperature[7]=%s, w.FailCode=%d, w.FailDesc=%s",
                                 w.Model, w.IP, w.Worker, w.MAC, w.ServerID, w.Status, w.Progress[0], w.Progress[1], w.Progress[2], w.Progress[3], w.Progress[4], w.Progress[5], w.Progress[6], w.Progress[7], w.PoolHashRate, w.SelfCalHashRate, w.WorkingAsic, w.FanSpeed[0], w.FanSpeed[1], w.FanSpeed[2], w.FanSpeed[3], w.FanSpeed[4], w.PoolAddress, w.WalletAddress, w.Account, w.Password, w.MinerOPFreq, w.PowerConsumption, 'NA', w.Temperature[0], w.Temperature[1], w.Temperature[2], w.Temperature[3], w.Temperature[4], w.Temperature[5], w.Temperature[6], w.Temperature[7], w.FailCode, w.FailDesc)
                n1 = 3
                # only for myConfig.Test is True. Get the lastest IP and CurrentHashrate from web.
                if myConfig.Test:
                    w.IP = strTestIP
                    w.PoolHashRate = fTestCurrentHashrate

                if w.FailCode == 2 or int(w.FailCode) == 3:
                    myTag = "red"
                elif w.FailCode == 1:
                    myTag = "yellow"
                elif w.Status == "offline":
                    w.FailCode = 4
                    w.FailDesc = "no cgminer found -> offline"
                    myTag = "green"
                elif w.FailCode == 0:
                    myTag = "normal"

                if w.FailCode == 1 and w.FailDesc == '':
                    w.FailDesc == "Worker's name not match to IP"

                if w.FailCode == 2 and w.FailDesc == '':
                    w.FailDesc == "ssh or scp failed"

                ret = tvWorker.insert("", tk.END, text=str(i+1),
                                      values=(w.Model, w.IP, w.Worker, w.MAC, w.ServerID, w.Status, w.Progress[0], w.Progress[1], w.Progress[2], w.Progress[3], w.Progress[4], w.Progress[5], w.Progress[6], w.Progress[7], w.PoolHashRate, w.SelfCalHashRate, w.WorkingAsic, w.FanSpeed[0], w.FanSpeed[1], w.FanSpeed[2], w.FanSpeed[3], w.FanSpeed[4], w.PoolAddress, w.WalletAddress, w.Account, w.Password, w.MinerOPFreq, w.PowerConsumption, 'NA', w.Temperature[0], w.Temperature[1], w.Temperature[2], w.Temperature[3], w.Temperature[4], w.Temperature[5], w.Temperature[6], w.Temperature[7], w.FailCode, w.FailDesc), tag=myTag)
                w.batch_id = batch[0]
                # w.datetime = datetime.now() # Change datetime from batch datetime to scan datetime for "Build Version=20221102-001"
                n1 = 4
                InsertWorkerToDB(cursor, w)
                n1 = 5
                CommitDB(conn)
                nWritten += 1
                n1 = 6
            except MySQLdb.Error as e:
                logger.error(f"%s MySQLdb.Error %d: %s (MariaDB)",
                             w.IP, e.args[0], e.args[1])
                RollbackDB(conn)
                n1 = 8
            except:
                logger.warnning(
                    "IP=%s has unknow exception (%d)", workerArray[i].IP, n1)
                n1 = 7
            finally:
                continue
    logger.info("%d of workers insert into table SCAN. batch_id=%d, batch_time=%s (%d)",
                nWritten, batch[0], batch[1].strftime('%Y-%m-%d %H:%M'), n1)
    CloseDB(conn, cursor)
    logger.info("Close the database n0=%d, n1=%d", n0, n1)
    onScanT1 = datetime.now()
    diff = onScanT1 - onScanT0
    logger.info("It takes %d seconds of procedure of %d records",
                int(diff.total_seconds()), nWritten)
    myConfig.bScan = True
    onShow1()
    btnShow1.config(fg="blue")
    if bLevelname:
        logger.handlers[0].setFormatter(logging.Formatter(strLogFormater2))
    if FHLog != None:
        FHLog.setFormatter(logging.Formatter(strLogFormater2))
    logger.warning(
        "====== End of Worker scanning, please check the UI of scanner.")
    if bLevelname:
        logger.handlers[0].setFormatter(logging.Formatter(strLogFormater1))
    if FHLog != None:
        FHLog.setFormatter(logging.Formatter(strLogFormater1))
    # btnScan.config(fg='black', bg='#f0f0f0')


onScanT0 = None
onScanT1 = None
myIPs = []


def onLoadIPList():
    global i
    i = 0
    if action.scan:  # if action.scan == True. The onScan will not running. Default action.scan is False.
        return
    action.scan = True  # Set to True to protect onScan running again.
    onScanT0 = datetime.now()
    filename = filedialog.askopenfilename(initialdir="./",
                                          title="Select a single column IPv4 text file",
                                          filetypes=(("Text files",
                                                      "*.txt"),
                                                     ("all files",
                                                      "*.*")))
    handleFile = open(filename, "r")
    workerArray.clear()  # array of worker. Clear it before scaning.
    # dictionary mapping IP to index in workerArray. Clear it before scaning.
    dictIPtoIndex.clear()  # clear the IP to Index dictonary
    tvWorker.delete(*tvWorker.get_children())  # clear the treeview of workers
    if myConfig.Home:
        logger.debug(
            "myConfig.Home=%d, Force to scan this worker no matter the MAC is found or not.", myConfig.Home)
    for line in handleFile:
        myIP = line.strip()
        myIPs.append(myIP)
        if myConfig.Verbose:
            logger.debug("%02d: IP=%s", i, myIP)

        tvWorker.insert("", tk.END, text=str(i+1),
                        values=("", myIP, "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""), tag="gray")
        w = worker()
        w.Number = i
        w.IP = myIP
        w.Ssh = 1
        w.bPowerRay = True
        w.FailCode = 0
        w.FailDesc = ''
        workerArray.append(w)
        dictIPtoIndex[myIP] = i
        i += 1
    handleFile.close()
    onScanT1 = datetime.now()
    diff = onScanT1 - onScanT0
    logger.info("It takes %d seconds to load the %d records of IPv4 to be scanned",
                int(diff.total_seconds()), i)


def onScanList():
    global i
    onScanT0 = datetime.now()
    for i in range(len(workerArray)):
        # Construct nmap command for Windows OS (nPlatform==1) and other OSs. Only check ssh port == 22
        # grep nmap result only for IP and ssh
        myIP = workerArray[i].IP
        logger.debug("The IP=%s", myIP)
        lstFrom = ip_to_int(myIP)
        if nPlatform == 2 or nPlatform == 3:
            if myConfig.Home:
                strNmap = "sudo nmap -n -p 22 " + myIP + " | grep '" + \
                    str(lstFrom[0]) + "\\|ssh'"
            else:
                strNmap = "sudo nmap -n -p 22 " + myIP + \
                    " | grep '" + str(lstFrom[0]) + "\\|ssh\\|MAC'"
        elif nPlatform == 1:
            if myConfig.Home:
                strNmap = "nmap -n -sT -T4 -p 22 " + myIP + \
                    " | Select-String -pattern '" + str(lstFrom[0]) + "|ssh'"
            else:
                strNmap = "nmap -n -sT -T4 -p 22 " + myIP + \
                    " | Select-String -pattern '" + \
                    str(lstFrom[0]) + "|ssh|MAC'"
        # if strNmap.find("sudo") >= 0:
        #    logger.warning(
        #        "Please check if you may need to enter the password of sudo command in the console or terminal")
        if (myConfig.Verbose):
            logger.debug("==== " + strNmap)

        # Run nmap and check how long nmap takes
        if nPlatform == 2 or nPlatform == 3:
            results = subprocess.Popen(
                strNmap, stdout=subprocess.PIPE, shell=True).communicate()[0].split(b"\n")
        else:
            results = subprocess.Popen(
                ["powershell", "-Command", strNmap], stdout=subprocess.PIPE).stdout

        # Scan each IP and make sure the port 22 is open and get MAC if has
        for bResult in results:
            strTmps = bResult.decode("utf-8").split(" ")
            # 1st line include IPv4. Get IPv4.
            if len(strTmps) > 8 and strTmps[7] == "recognized" and nPlatform == 1:
                logger.warning(myIP + " " + bResult)
                logger.warning(
                    "Please check the nmap installed or the $Env:path include path of namp of Windows and quit the program.")
                quit()
            if strTmps[0] == "22/tcp":  # 2nd line include ssh port 22 is 'open' or 'close'
                if strTmps[1].lower() == "open":
                    nSsh = 1
                else:
                    nSsh = 0
                workerArray[i].Ssh = nSsh
                # only take care of the worker when it's ssh/22 is "open".
                logger.info(
                    "Port 22 of '%s' is '%s'", myIP, strTmps[1])
                if nSsh == 1:
                    workerArray[i].Number = i
                    workerArray[i].bPowerRay = True
                    workerArray[i].Ssh = nSsh
                if myConfig.Home:
                    if nSsh == 1:
                        workerArray[i].bPowerRay = True
            if strTmps[0] == "MAC":  # it's a MAC address
                if nPlatform == 1:
                    logger.info("Nmap scan result '%s'",
                                bResult.decode("utf-8").rstrip())  # Windows remove "\r\n"
                else:
                    logger.info("Nmap scan result '%s'",
                                bResult.decode("utf-8").rstrip())

                if strTmps[2][0:8] in {"68:5E:6B", "F4:3E:66"}:
                    logger.info(
                        "Only check the MAC(%s) OUI (The irst 6-digits of '%s') belong to (PowerRay) or '%s' (Bee Computing)", strTmps[2], "68:5E:6B", "F4:3E:66")
                    if nSsh == 1:
                        workerArray[i].bPowerRay = True
                else:
                    logger.warning(
                        "The MAC OUI (The first 6-digits of '%s') doesn't belong to '%s' (PowerRay) or '%s' (Bee Computing). Skit it.", strTmps[2], "68:5E:6B", "F4:3E:66")
                    workerArray[i].MAC = strTmps[2]
                    workerArray[i].bPowerRay = True
                    workerArray[i].FailCode = 2
                    workerArray[i].FailDesc = \
                        "The MAC OUI (" + \
                        strTmps[2][0:8] + ") is not valid"
                    if myConfig.Home:  # if myConfig.Home != 0 to ignore MAC address OUI checking
                        logger.info(
                            "myConfig.Home = %d != 0 to ignore MAC OUI checking", myConfig.Home)
                        if nSsh == 1:
                            workerArray[i].bPowerRay = True
                    workerArray[i].Ssh = 1

    action.scan = False  # finish the scan for all IPs
    logger.info(
        "Finish IP & port=22 scan and set action.scan to False and please wait for brower launch for a moment")

    # Start to gather information of each worker when it's ssh/22 is "open"
    for i in range(len(workerArray)):
        if action.scan:
            return
        # ssh to worker's IP. username=root, no password
        myIP = workerArray[i].IP
        # Change datetime from batch datetime to scan datetime for "Build Version=20221102-001"
        workerArray[i].datetime = datetime.now()
        logger.info("======== ssh to " + myIP)
        client, strReturn = sshToWoker(myIP)
        if client == None:
            workerArray[i].FailDesc = "Can not ssh to " + myIP
            workerArray[i].FailCode = 2
            continue

        # Create /root/scripts/ch and copy all scripts from local to worker. And change the *.sh to executable
        stdin, stdout, stderr = client.exec_command(
            "rm -rf " + strScriptsPath + "; mkdir -p " + strScriptsPath)
        logger.info(
            "Delete %s and re-created on the worker.", strScriptsPath)
        stdout.close()
        # scp all scripts and python files to worker
        if nPlatform == 1:  # Windows 10/11 or Server
            # Create a PowerShell scrip file go.ps1
            # C:
            # cd $HOME\ch
            # ..\AppData\Local\Programs\Python\Python310\python.exe $HOME\ch\PowerRayETC.[ver].py
            a = "\\"
            filename = "C:\\Users\\" + os.getlogin() + a + "ch\\scripts\\ch"
            # filename = PureWindowsPath(myConfig.scpscripts)
            logger.info(
                "Copy all the scripts from folder '%s'", str(filename))
            cmd1 = "scp -p -C -r -4 " + str(filename) + " root@" + \
                workerArray[i].IP + ":/root/scripts"
            cmd2 = "chmod +x " + strScriptsPath + "*.sh"
            ret = subprocess.run(cmd1, shell=True, stdout=subprocess.PIPE,
                                 stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            if ret.returncode == 0:
                logger.info(
                    "Run '%s' on Windows. The return = %d (0=OK 1=NG)", cmd1, ret.returncode)
            else:
                logger.warning(
                    "Run '%s' on Windows. The return = %d (0=OK 1=NG)", cmd1, ret.returncode)
            lines = ret.stdout.decode("utf-8")
            errlines = ret.stderr.decode("utf-8")
            # ret.stdout.close()
            # ret.stderr.close()
            logger.info("len of stdout=%d, stderr=%d",
                        len(lines), len(errlines))
            if len(lines) > 0:
                logger.info(lines[0:-1])
            if len(errlines) > 0:
                strTmps = errlines.split("\r\n")
                for strTmp in strTmps:
                    if len(strTmp) > 0 and strTmp[-1] == "\n":  # v1.03
                        strTmp = strTmp[0:-1]
                    if len(strTmp) > 0:
                        logger.warning(strTmp)
                if len(errlines) > 12 and errlines.find("known_host") and len(lines) == 0:
                    logger.warning(
                        "Known host is conflict. Remove it from the file and try again.")
                    cmd3 = r"C:\windows\system32\Openssh\ssh-keygen.exe -R " + myIP + " 2>&1 | out-null"
                    logger.info(
                        "Run '%s' to remove it from local known hosts.", cmd3)
                    os.system(cmd3)
            if ret.returncode == 0:
                stdin, stdout, stderr = client.exec_command(cmd2)
                logger.info("Run '%s' on worker.", cmd2)
                stdout.close()
            else:
                # Run copy scripts again
                logger.info(
                    "Run '%s' again on IP=%s", cmd1, workerArray[i].IP)
                ret2 = subprocess.run(cmd1, shell=True, stdout=subprocess.PIPE,
                                      stdin=subprocess.PIPE, stderr=subprocess.PIPE)
                if ret2.returncode == 0:
                    stdin, stdout, stderr = client.exec_command(cmd2)
                    stdout.close()
                else:
                    logger.error("Please check the IP=%s why can't copy scripts.",
                                 workerArray[i].IP)
                    logger.error("The faild command='%s'", cmd2)
                    workerArray[i].FailCode = 2
                    workerArray[i].FailCode = "scp scripts to worker failed."
                    continue
        else:
            cmd1 = "scp ./scripts/ch/*.* root@" + \
                workerArray[i].IP + ":" + \
                strScriptsPath + ". > /dev/null 2>&1"
            logger.info(
                "Run '%s' on local Linux like OS.", cmd1)
            os.system(cmd1)
            cmd2 = "chmod +x " + strScriptsPath + "*.sh"
            logger.info("Run '%s' on worker.", cmd2)
            stdin, stdout, stderr = client.exec_command(cmd2)
            lines = stdout.readlines()
            stdout.close()
            if len(lines) > 0:
                for line in lines:
                    logger.info(line)
            errlines = stderr.readlines()
            if len(errlines) == 0:
                logger.info("Run '%s' successfully", cmd2)
            else:
                for line in errlines:
                    logger.error(line)
                logger.error("Run '%' failed", cmd2)
            stderr.close()
        # sleep(1)

        # Get worker's MAC address of br-lan and worker's name
        cmd = strScriptsPath + "getMACnWorker.sh 14400"
        stdin, stdout, stderr = client.exec_command(cmd)
        logger.info("Run '%s' on worker.", cmd)
        errLines = stderr.readlines()
        if len(errLines) > 0 and errLines[0].find("Permission"):
            workerArray[i].MAC = "NA"
            workerArray[i].Worker = "NA"
            logger.warning(
                "getMACnWorker.sh permission denied. Set MAC and Worker as 'NA'")
        else:
            lines = stdout.readlines()
            workerArray[i].MAC = lines[0][:-1]
            if lines[1][:-1] == "IOSCAN":
                workerArray[i].Worker = ""
            else:
                workerArray[i].Worker = lines[1][:-1]
            logger.info("getMACnWorker.sh return MAC=%s and Worker='%s'",
                        workerArray[i].MAC, workerArray[i].Worker)
            if lines[1][:-1] == "IOSCAN" and lines[2][:-1] == "4hr":
                workerArray[i].FailCode = 1
                workerArray[i].FailDesc = "More than 4 hours still in IOSCAN state"
        stderr.close()
        stdout.close()

        # if /root/Model is not exist. Query the MS-SQL DB and write Model and ServerID to /root
        cmd = "ls /root/Model"
        stdin, stdout, stderr = client.exec_command(cmd)
        lines = stderr.readlines()
        stderr.close()

        bException = False
        nMSSQL = 0
        if len(lines) > 0 and lines[0].find("No such file or directory") != -1:
            logger.warning(
                "Run  %s and return 'No such file or directory' then querty MS-SQL and wrtie to /root/Model and /root/ServerID", cmd)
            # Querty MS-SQL and wrtie to /root/Model amd /root/ServerID (only for production site)
            # Connect to database
            conn = None
            cursor = None
            try:
                # server = '192.168.1.5'
                # database = 'Darwin_SB'
                # username = 'test123'
                # password = 'test'
                server = myConfig.mssqlHost
                database = myConfig.mssqlDatabase
                username = myConfig.mssqlUser
                password = myConfig.mssqlPassword
                conn = pymssql.connect(server=server, user=username,
                                       password=password, database=database)
                nMSSQL = 1
                if conn:
                    logger.info(
                        "Connect to MS-SQL production database successfully")
                    cursor = conn.cursor()
                    strModel = 'NA'
                    strServerID = 'NA'
                    if cursor:
                        strMAC = workerArray[i].MAC
                        cmd = "exec " + myConfig.mssqlStoreProcedure + "'"+strMAC+"';"
                        cursor.execute(cmd)
                        logger.info(
                            "Run MS-SQL stored procedure '%s'", cmd)
                        row = cursor.fetchall()
                        if row and len(row[0]) == 2:
                            if row[0][0] is None:
                                logger.warning("IP=%s has no ServerID in MS-SQL",
                                               workerArray[i].IP)
                            else:
                                strServerID = row[0][0]
                                logger.info(
                                    "The ServerID=%s from MS-SQL Stored Procedure", strServerID)
                            if row[0][1] is None:
                                logger.warning("IP=%s has no strModel in MS-SQL",
                                               workerArray[i].IP)
                            else:
                                strModel = row[0][1]
                                logger.info(
                                    "The Model=%s from MS-SQL Stored Procedure", strModel)
                            workerArray[i].ServerID = strServerID
                            workerArray[i].Model = strModel
                            cmd = "echo " + strServerID + " > /root/ServerID; echo " + strModel + " > /root/Model"
                            stdin, stdout, stderr = client.exec_command(cmd)
                            logger.info(
                                "echo ServerID & Model in worker's /root directory")
            except Exception as e:
                print(e)
                pass

        # Get Model from /root/Model
        cmd = strScriptsPath + "getModel.sh"
        stdin, stdout, stderr = client.exec_command(cmd)
        lines = stdout.readlines()
        if len(lines) > 0 and lines[0].find("No such file or directory") != -1:
            logger.warning(
                "Run '%s' and can't find /root/Model. Set /root/Model as 'NA'")
            workerArray[i].Model = 'NA'
        elif len(lines) > 0:
            strModel = lines[0][:-1]
            logger.info("Model=%s", strModel)
            workerArray[i].Model = strModel
        else:
            logger.warning(
                "Unknown reason can't get /root/Model. echo 'NA' > /root/Model")
            workerArray[i].Model = 'NA'
        stdout.close()

        # Get ServerID from /root/ServerID
        strServerID = ''
        strModel = ''
        stdin, stdout, stderr = client.exec_command(
            strScriptsPath + "getServerID.sh")
        lines = stdout.readlines()
        if len(lines) > 0 and lines[0].find("No such file or directory") != -1:
            logger.warning(
                "Can't find /root/ServerID. echo 'NA' > /root/ServerID")
            workerArray[i].ServerID = 'NA'
        elif len(lines) > 0:
            strServerID = lines[0][:-1]
            workerArray[i].ServerID = strServerID
        else:
            workerArray[i].ServerID = 'NA'
        stdout.close()

        logger.info("IP=%s, Worker=%s, MAC=%s, Model=%s, ServerID=%s",
                    workerArray[i].IP, workerArray[i].Worker, workerArray[i].MAC, strModel, strServerID)

        # Get miner's status from different combination of situations
        cmd = strScriptsPath + "getStatus.sh 300"
        if workerArray[i].FailCode == 0:
            workerArray[i].FailDesc = ''
        logger.info("run remote command=%s", cmd)
        stdin, stdout, stderr = client.exec_command(cmd)
        lines = stdout.readlines()
        errlines = stderr.readlines()
        stderr.close()
        stdout.close()
        logger.info("len of stdout=%d, stderr=%d",
                    len(lines), len(errlines))
        for line in errlines:
            logger.error(line[:-1])
        strStatus = "Unknown"
        if len(lines) >= 1:
            strStatus = lines[0][:-1]
            if strStatus[0:8] == "FailCode":
                logger.error(strStatus)
                strTmps = strStatus.split(',')
                strStatus = "Fail"
                workerArray[i].Status = strStatus
                workerArray[i].FailCode = strTmps[1]
                workerArray[i].FailDesc = strTmps[2]
                if len(lines) >= 2:
                    strStatus = lines[1][:-1]
                    if strStatus == "IOSCAN":
                        logger.info("strStatus=%s", strStatus)
            elif strStatus[0:6] == "IOSCAN":
                strStatus = "IOSCAN"
        workerArray[i].Status = strStatus

        if strStatus == "DAG":
            for line in lines:
                line = line[:-1]
                if (line != "DAG"):
                    strProgress = line[:-1]
                    pos1 = strProgress.find("/")
                    if pos1 != -1:
                        strP1 = strProgress[pos1-3:pos1]  # 前面為、二位數，或三位數
                        if strP1[0] == 'y':
                            strP1 = strProgress[pos1-1:pos1]  # 前面為一位數
                        strP2 = strProgress[pos1+1:pos1+5]
                        nP1 = int(strP1)
                        nP2 = int(strP2)
                        fPercent = float(nP1/nP2)*100
                        strTemp = str(fPercent)
                        pos2 = strTemp.find(".")
                        if pos2 != -1:
                            strPercent = strTemp[0:pos2+3] + "%"
                            workerArray[i].Progress.append(strPercent)
        elif strStatus == "IOSCAN":
            for line in lines:
                line = line[:-1]
                if line[0:8] == "FailCode":
                    continue
                if (line != "IOSCAN"):
                    nP1 = int(line)
                    nP2 = 1152*8
                    fPercent = float(nP1/nP2)*100
                    strTemp = str(fPercent)
                    pos2 = strTemp.find(".")
                    if pos2 != -1:
                        strPercent = strTemp[0:pos2+3] + "%"
                        workerArray[i].Progress.append(strPercent)
        for j in range(8-len(workerArray[i].Progress)):
            workerArray[i].Progress.append('NA')
        stdout.close()

        if strStatus in {"Mining"}:
            if workerArray[i].Worker != '':
                strTime, strHashRateMs = myEthermineApi.getWorkerCurrentStats(
                    workerArray[i].WalletAddress, strWorker=workerArray[i].Worker)
                logger.info("return time=%s, HashRate=%s M/s",
                                 strTime, strHashRateMs)
            if strTime == '':
                for j in range(len(myConfig.URL)):
                    if workerArray[i].WalletAddress.find(myConfig.URL[j]) >= 0:
                        if j == 0:
                            strWalletAddress = myConfig.URL[1]
                        else:
                            strWalletAddress = myConfig.URL[0]
                strTime, strHashRateMs = myEthermineApi.getWorkerCurrentStats(
                    strWalletAddress, strWorker=workerArray[i].Worker)
                logger.info("return time=%s, HashRate=%s M/s",
                                 strTime, strHashRateMs)
            #workerArray[i].datetime = datetime.now()
            workerArray[i].PoolHashRate = strHashRateMs
        else:
            workerArray[i].PoolHashRate = 0

        # Get board temperatures from "python3 /root/ft930_control/FT930_control.py". PR_8X, PR_1U and PR_SB has different number of board temperatures
        cmd = strScriptsPath + "getBoardTemp.sh"
        stdin, stdout, stderr = client.exec_command(cmd)
        lines = stdout.readlines()
        errlines = stderr.readlines()
        for line in errlines:
            logger.info(line[:-1])
        for line in lines:
            line = line[:-1]
            workerArray[i].Temperature.append(line)
        for j in range(8-len(workerArray[i].Temperature)):
            workerArray[i].Temperature.append('NA')
        stderr.close()
        stdout.close()

        # Install smbus2 if not installed
        transport = client.get_transport()
        transport.set_keepalive(60)
        bSmbus2 = False
        cmd = "python3 " + strScriptsPath + "test_smb2.py"
        stdin, stdout, stderr = client.exec_command(cmd)
        errLines = stderr.readlines()
        for line in errLines:
            if line[:-1].find("No module named 'smbus2'") >= 0:
                bSmbus2 = True
                logger.warning(
                    "No module named 'smbus2' on IP=%s", workerArray[i].IP)
        stderr.close()

        if bSmbus2:
            # cmd = "pip3 install --trusted-host pypi.org smbus2"
            cmd = "python3 -m pip install --trusted-host files.pythonhosted.org --trusted-host pypi.org --trusted-host pypi.python.org smbus2"
            logger.info("Install smbus2 via '%s'", cmd)
            stdin, stdout, stderr = client.exec_command(cmd)
            lines = stdout.readlines()
            for line in lines:
                logger.info(line[:-1])
            errlines = stderr.readlines()
            for line in errlines:
                logger.warning(line[:-1])
            stdout.close()
            stderr.close()

        # Get FAN speed from ~/scripts/ch/getFanSpeed.sh
        nFanSpeed = 0
        cmd = strScriptsPath + "getFanSpeed.sh 2>/dev/null"
        logger.info("Before run '%s'", cmd)
        try:
            stdin, stdout, stderr = client.exec_command(cmd)
            logger.info("After run '%s'", cmd)
            errlines = stderr.readlines()
            lines = stdout.readlines()
            stderr.close()
            stdout.close()
            logger.info("len of stdout=%d, stderr=%d",
                        len(lines), len(errlines))
            for line in errlines:
                logger.error(line[:-1])
            for line in lines:
                logger.info("'" + line[:-1] + "'")
                strTmp = line[:-1]
                if strTmp == 'Initializing PMBUS... ':
                    workerArray[i].FanSpeed.append('NA')
                    nFanSpeed += 1
                    break
                else:
                    nPos = strTmp.find('.')
                    line = line[0:nPos]
                    workerArray[i].FanSpeed.append(line)
                nFanSpeed += 1
        except Exception as e:
            logger.error(e)
        if nFanSpeed < 5:
            for j in range(nFanSpeed, 5):
                workerArray[i].FanSpeed.append("NA")
                logger.info("append('NA') for %d", j)

        # Get WorkingAsic from /root/log/messages or /tmp/log/messages for different control board
        if (workerArray[i].Hostname == "RTD1619B"):
            stdin, stdout, stderr = client.exec_command(
                "tail -500 /root/log/messages | grep 'SOLUTION FOUND' | awk '{print $12 $15}'")
        else:
            stdin, stdout, stderr = client.exec_command(
                "tail -500 /tmp/log/messages | grep 'SOLUTION FOUND' | awk '{print $12 $15}'")
        lines = stdout.readlines()
        for line in lines:
            line = line[:-2]
            nHashboard = int(line[2]) - 1
            nAsic = int(line[0])
            workerArray[i].HashboardAsic[nHashboard][nAsic] = 1
        for ii in range(4):
            for jj in range(2):
                if workerArray[i].HashboardAsic[ii][jj]:
                    workerArray[i].WorkingAsic += 1
        time.sleep(1)
        stdout.close()
        client.close()

    try:
        # Get CurrentHashrate from pool web site via WebDriver.
        # Important: the WebDriver shall be the same version as the web browser
        # nWebDriver = args.webdriver
        options = Options()
        options.use_chromium = True
        options.headless = True
        # options.add_argument(r"headless")
        options.add_argument(r"disable-gpu")
        if nWebdriver == 1:
            driver = webdriver.Edge(service=s, options=options)
        elif nWebdriver == 2:
            driver = webdriver.Edge(service=s, options=options)
        # "https://etc.ethermine.org/miners/20c0ac4e73ed4db87fef692991c0f4becff93cbc/dashboard")
        # "https://etc.ethermine.org/miners/57fc699ad1249f65759e1af273e26350dece1eb6/dashboard")

        logger.info("Launch the browser to parse the worker's CurrentHashrate")
        for walletAddress in myConfig.URL:
            strURL = "https://etc.ethermine.org/miners/" + walletAddress + "/dashboard"
            logger.info("Launch '%s'", strURL)
            driver.get(strURL)
            driver.implicitly_wait(60)
            driver.minimize_window()

            elements = driver.find_elements(By.CLASS_NAME, 'table-body')

            for element in elements:
                x = element.get_attribute('innerHTML')
                if myConfig.Verbose >= 6:
                    logger.info("innerHTML=%s", str(x))
                soup = BeautifulSoup(x, "html.parser")
                if myConfig.Verbose >= 5:
                    logger.info("soup=%s", str(soup))
                rows = soup.find_all("td", class_="string")
                if myConfig.Verbose >= 4:
                    logger.info("rows=%s", str(rows))
                for row in rows:
                    if myConfig.Verbose >= 3:
                        logger.info("row=%s", str(row))
                    if len(row.attrs) == 4:  # Name
                        strIP = row.text.replace("-", ".")

                rows = soup.find_all("td", class_="number")
                if myConfig.Verbose >= 4:
                    logger.info("rows=%s", str(rows))
                for row in rows:
                    if myConfig.Verbose >= 3:
                        logger.info("row=%s", str(row))
                    if row.attrs['data-label'] == "Current Hashrate":
                        if myConfig.Verbose >= 2:
                            logger.info(
                                "row.attrs['data-label']=%s", row.attrs['data-label'])
                        fCurrentHashrate = 0.0
                        if row.text != '0':
                            if myConfig.Verbose >= 2:
                                logger.info(
                                    "row.text=%s, row.attrs['unit']=%s", row.text, row.attrs['unit'])
                            if row.attrs['unit'] == "GH/s":
                                fCurrentHashrate = float(row.text)*1000
                                if myConfig.Verbose >= 1:
                                    logger.info("IP=%s, unit=%s, unit=%s -> %7.1f M/s",
                                                strIP, row.text, row.attrs['unit'], fCurrentHashrate)
                            else:
                                fCurrentHashrate = float(row.text)
                                if myConfig.Verbose >= 1:
                                    logger.info(
                                        "IP=%s, unit = None -> current Hashrate = %7.1f M/s", strIP, fCurrentHashrate)

                strTestIP = strIP
                fTestCurrentHashrate = fCurrentHashrate
                if strIP in dictIPtoIndex:
                    workerArray[dictIPtoIndex[strIP]
                                ].PoolHashRate = fCurrentHashrate
                    workerArray[dictIPtoIndex[strIP]].Web = 1
                    logger.info(
                        "IP=%s current Hashrate = %10.3f M/s", strIP, fCurrentHashrate)
        driver.quit()
        logger.info("Close the browser")
    except Exception as e:
        logger.error('webdriver.Exception = ', e)

    n0 = 0
    # workerArray.clear()
    # dictIPtoIndex.clear()  # dictionary mapping IP to index in workerArray
    # clear the tvWorker treeview before start to insert the row data
    tvWorker.delete(*tvWorker.get_children())
    logger.info("Insert Worker's informatin into table SCAN")
    # try:
    n0 = 1
    conn = ConnectToDB()
    n0 = 2
    cursor = GetCursorDB(conn)
    n0 = 3
    batch = GetBatchID(cursor)
    n0 = 4

    # Insert information of each worker into tktree when it's ssh/22 is "open"
    nWritten = 0
    n1 = 0
    for i in range(len(workerArray)):
        if workerArray[i].bPowerRay:
            if workerArray[i].PoolHashRate == None:
                workerArray[i].PoolHashRate = 0
            w = workerArray[i]
            n1 = 0
            try:
                n1 = 1
                myTag = "normal"
                if not (w.Worker == None or w.Worker == ""):
                    if not w.Status == "offline":
                        strWorker = w.Worker
                        if validate(strWorker.replace("-", ".")) and not strWorker.replace("-", ".") == w.IP:
                            myTag = "red"
                n1 = 2
                w.Model = "" if w.Model == None else w.Model
                w.IP = "" if w.IP == None else w.IP
                w.Worker = "" if w.Worker == None else w.Worker
                w.MAC = "" if w.MAC == None else w.MAC
                w.ServerID = "" if w.ServerID == None else w.ServerID
                w.Status = "" if w.Status == None else w.Status
                if len(w.Progress) < 8:
                    for j in range(8-len(w.Progress)):
                        w.Progress.append("NA")
                w.Progress[0] = "" if w.Progress[0] == None else w.Progress[0]
                w.Progress[1] = "" if w.Progress[1] == None else w.Progress[1]
                w.Progress[2] = "" if w.Progress[2] == None else w.Progress[2]
                w.Progress[3] = "" if w.Progress[3] == None else w.Progress[3]
                w.Progress[4] = "" if w.Progress[4] == None else w.Progress[4]
                w.Progress[5] = "" if w.Progress[5] == None else w.Progress[5]
                w.Progress[6] = "" if w.Progress[6] == None else w.Progress[6]
                w.Progress[7] = "" if w.Progress[7] == None else w.Progress[7]
                w.PoolHashRate = "" if str(
                    w.PoolHashRate) == None else str(w.PoolHashRate)
                w.SelfCalHashRate = "" if w.SelfCalHashRate == None else w.SelfCalHashRate
                w.WorkingAsic = "" if str(
                    w.WorkingAsic) == None else str(w.WorkingAsic)
                if len(w.FanSpeed) < 5:
                    for j in range(5-len(w.FanSpeed)):
                        w.FanSpeed.append("NA")
                w.FanSpeed[0] = "" if w.FanSpeed[0] == None else w.FanSpeed[0]
                w.FanSpeed[1] = "" if w.FanSpeed[1] == None else w.FanSpeed[1]
                w.FanSpeed[2] = "" if w.FanSpeed[2] == None else w.FanSpeed[2]
                w.FanSpeed[3] = "" if w.FanSpeed[3] == None else w.FanSpeed[3]
                w.FanSpeed[4] = "" if w.FanSpeed[4] == None else w.FanSpeed[4]
                w.PoolAddress = "" if w.PoolAddress == None else w.PoolAddress
                w.WalletAddress = "" if w.WalletAddress == None else w.WalletAddress
                w.Account = "" if w.Account == None else w.Account
                w.Password = "" if w.Password == None else w.Password
                w.MinerOPFreq = "" if w.MinerOPFreq == None else w.MinerOPFreq
                w.PowerConsumption = "" if w.PowerConsumption == None else w.PowerConsumption
                w.DHCPorFixedIP = "" if w.DHCPorFixedIP == None else w.DHCPorFixedIP
                if len(w.Temperature) < 8:
                    for j in range(8-len(w.Temperature)):
                        w.Temperature.append("NA")
                w.Temperature[0] = "" if w.Temperature[0] == None else w.Temperature[0]
                w.Temperature[1] = "" if w.Temperature[1] == None else w.Temperature[1]
                w.Temperature[2] = "" if w.Temperature[2] == None else w.Temperature[2]
                w.Temperature[3] = "" if w.Temperature[3] == None else w.Temperature[3]
                w.Temperature[4] = "" if w.Temperature[4] == None else w.Temperature[4]
                w.Temperature[5] = "" if w.Temperature[5] == None else w.Temperature[5]
                w.Temperature[6] = "" if w.Temperature[6] == None else w.Temperature[6]
                w.Temperature[7] = "" if w.Temperature[7] == None else w.Temperature[7]
                w.FailDesc = "" if w.FailDesc == None else w.FailDesc

                if myConfig.Verbose >= 1:
                    logger.info("w.Model=%s, w.IP=%s, w.Worker=%s, w.MAC=%s, w.ServerID=%s, w.Status=%s, w.Progress[0]=%s, w.Progress[1]=%s, w.Progress[2]=%s, w.Progress[3]=%s, w.Progress[4]=%s, w.Progress[5]=%s, w.Progress[6]=%s, w.Progress[7]=%s, w.PoolHashRate=%s, w.SelfCalHashRate=%s, w.WorkingAsic=%s, w.FanSpeed[0]=%s, w.FanSpeed[1]=%s, w.FanSpeed[2]=%s, w.FanSpeed[3]=%s, w.FanSpeed[4]=%s, w.PoolAddress=%s, w.WalletAddress=%s, w.Account=%s, w.Password=%s, w.MinerOPFreq=%s, w.PowerConsumption=%s, 'NA'=%s, w.Temperature[0]=%s, w.Temperature[1]=%s, w.Temperature[2]=%s, w.Temperature[3]=%s, w.Temperature[4]=%s, w.Temperature[5]=%s, w.Temperature[6]=%s, w.Temperature[7]=%s, w.FailCode=%d, w.FailDesc=%s",
                                w.Model, w.IP, w.Worker, w.MAC, w.ServerID, w.Status, w.Progress[0], w.Progress[1], w.Progress[2], w.Progress[3], w.Progress[4], w.Progress[5], w.Progress[6], w.Progress[7], w.PoolHashRate, w.SelfCalHashRate, w.WorkingAsic, w.FanSpeed[0], w.FanSpeed[1], w.FanSpeed[2], w.FanSpeed[3], w.FanSpeed[4], w.PoolAddress, w.WalletAddress, w.Account, w.Password, w.MinerOPFreq, w.PowerConsumption, 'NA', w.Temperature[0], w.Temperature[1], w.Temperature[2], w.Temperature[3], w.Temperature[4], w.Temperature[5], w.Temperature[6], w.Temperature[7], w.FailCode, w.FailDesc)
                n1 = 3
                # only for myConfig.Test is True. Get the lastest IP and CurrentHashrate from web.
                if myConfig.Test:
                    w.IP = strTestIP
                    w.PoolHashRate = fTestCurrentHashrate

                if w.FailCode == 2 or int(w.FailCode) == 3:
                    myTag = "red"
                elif w.FailCode == 1:
                    myTag = "yellow"
                elif w.Status == "offline":
                    myTag = "green"
                    w.FailCode = 4
                    w.FailDesc = "no cgminer found -> offline"
                elif w.FailCode == 0:
                    myTag = "normal"

                if w.FailCode == 1 and w.FailDesc == '':
                    w.FailDesc == "Worker's name not match to IP"

                if w.FailCode == 2 and w.FailDesc == '':
                    w.FailDesc == "ssh or scp failed"

                ret = tvWorker.insert("", tk.END, text=str(i+1),
                                      values=(w.Model, w.IP, w.Worker, w.MAC, w.ServerID, w.Status, w.Progress[0], w.Progress[1], w.Progress[2], w.Progress[3], w.Progress[4], w.Progress[5], w.Progress[6], w.Progress[7], w.PoolHashRate, w.SelfCalHashRate, w.WorkingAsic, w.FanSpeed[0], w.FanSpeed[1], w.FanSpeed[2], w.FanSpeed[3], w.FanSpeed[4], w.PoolAddress, w.WalletAddress, w.Account, w.Password, w.MinerOPFreq, w.PowerConsumption, 'NA', w.Temperature[0], w.Temperature[1], w.Temperature[2], w.Temperature[3], w.Temperature[4], w.Temperature[5], w.Temperature[6], w.Temperature[7], w.FailCode, w.FailDesc), tag=myTag)
                w.batch_id = batch[0]
                w.datetime = datetime.now()
                n1 = 4
                InsertWorkerToDB(cursor, w)
                n1 = 5
                CommitDB(conn)
                nWritten += 1
                n1 = 6
            except MySQLdb.Error as e:
                logger.error(f"%s MySQLdb.Error %d: %s (MariaDB)",
                             w.IP, e.args[0], e.args[1])
                RollbackDB(conn)
                n1 = 8
            except:
                logger.warnning(
                    "IP=%s has unknow exception (%d)", workerArray[i].IP, n1)
                n1 = 7
            finally:
                continue
    logger.info("%d of workers insert into table SCAN. batch_id=%d, batch_time=%s (%d)",
                nWritten, batch[0], batch[1].strftime('%Y-%m-%d %H:%M'), n1)
    # except:
    #    logger.error("IP=%s has unknow exception (%d)",
    #                 workerArray[i].IP, n1)
    #    n0 = 5
    CloseDB(conn, cursor)
    logger.info("Close the database n0=%d, n1=%d", n0, n1)
    onScanT1 = datetime.now()
    diff = onScanT1 - onScanT0
    logger.info("It takes %d seconds of procedure of %d records",
                int(diff.total_seconds()), i)
    myConfig.bScan = True
    onShow1()
    btnShow1.config(fg="blue")
    logger.info(
        "End of Worker scanning, please check the UI of scanner.")


def resize(event):
    if str(event.widget) == "." and event.width >= 1235:
        if nPlatform == 1:
            frame7.place(x=420, y=185, height=555+(event.height -
                         myConfig.RootnHeight), width=750+(event.width-myConfig.RootWidth)+50)
            #tvWorker.place(relx=0.01, rely=0.01, height=frame7.winfo_height() - 30, width=frame7.winfo_width() - 30)
            tvWorker.place(relx=0.01, rely=0.01, height=490+(event.height -
                                                             myConfig.RootnHeight), width=750+(event.width-myConfig.RootWidth))
        else:
            frame7.place(x=420, y=170, height=555+(event.height -
                         myConfig.RootnHeight), width=750+(event.width-myConfig.RootWidth)+50)
            tvWorker.place(relx=0.01, rely=0.01, height=frame7.winfo_height(
            ) - 57, width=frame7.winfo_width() - 45)
        if nPlatform == 1:
            frame2.place(x=420, y=5, height=145, width=800 +
                         (event.width-myConfig.RootWidth))
            btnQuit.place(x=1120+(event.width-myConfig.RootWidth),
                          y=155, height=30, width=100)
            frame61.place(x=10, y=520, height=220+(event.height -
                                                   myConfig.RootnHeight), width=130)
            frame62.place(x=150, y=520, height=220+(event.height -
                                                    myConfig.RootnHeight), width=260)
            sby.place(relx=0.975, rely=0.015, width=22, height=517 +
                      (event.height - myConfig.RootnHeight))
            sbx.place(relx=0.01, rely=0.965, width=750 +
                      (event.width-myConfig.RootWidth), height=22)
            # sby.place(relx=1-22/frame7.winfo_width(), rely=0.015,
            #          width=22, height=490+(event.height - myConfig.RootnHeight)+20)
            # sbx.place(relx=0.01, rely=1-26/frame7.winfo_height(),
            #          width=frame7.winfo_width()+630, height=22)
            # print(frame7.winfo_width())
            # print(frame7.winfo_height())
        else:
            frame2.place(x=420, y=5, height=125, width=800 +
                         (event.width-myConfig.RootWidth))
            btnQuit.place(x=1120+(event.width-myConfig.RootWidth),
                          y=137, height=30, width=100)
            frame61.place(x=10, y=510, height=215+(event.height -
                                                   myConfig.RootnHeight), width=130)
            frame62.place(x=150, y=510, height=215+(event.height -
                                                    myConfig.RootnHeight), width=260)
            sby.place(relx=1-28/frame7.winfo_width(), rely=0.01,
                      width=22, height=frame7.winfo_height() - 32)
            sbx.place(relx=0.01, rely=1-30/frame7.winfo_height(),
                      width=frame7.winfo_width() - 45, height=22)


if __name__ == "__main__":
    # create logger
    if not os.path.exists("log"):
        os.makedirs("log")
    # Load logging.conf
    logging.config.fileConfig('logging.conf')
    console_handler = logging.StreamHandler()
    logger = logging.getLogger('PowerRayETC')

    myEthermineApi = EthermineApi(logger)

    strLogFormater1 = vars(logger.handlers[0].formatter)['_fmt']
    strTmps = strLogFormater1.split(" ")
    for strTmp in strTmps:
        if strTmp.find("levelname") >= 0:
            strTemps = strTmp.split("-")
            if len(strTemps) == 2:
                strTemp = strTemps[1][:-1]
                bLevelname = True
                index = strTmps.index(strTmp)
                break
    if bLevelname:
        strLogFormater2 = strLogFormater1.replace(
            "%(levelname)-8s", "INFO    ")
    else:
        strLogFormater2 = strLogFormater1

    logger.handlers[0].setFormatter(logging.Formatter(strLogFormater2))

    rootlogger = logging.getLogger('')
    for h in rootlogger.__dict__['handlers']:
        if h.__class__.__name__ == 'RotatingFileHandler':
            FHLog = h
            FHLog.setFormatter(logging.Formatter(strLogFormater2))
            break
    logger.warning('====== Start to of PowerRayETC')
    strTitle = "{0}{1:04.2f} {2}".format(
        "==== PowerRay ETC Mining Dashboard - v", POWERRAY_ETC_VERSION, POWERRAY_ETC_BUILD_VERSION)
    logger.warning(strTitle)
    if bLevelname:
        logger.handlers[0].setFormatter(logging.Formatter(strLogFormater1))
    if FHLog != None:
        FHLog.setFormatter(logging.Formatter(strLogFormater1))
    root = tk.Tk()
    root.title(strTitle)
    root.tk.call('wm', 'iconphoto', root._w,
                 tk.PhotoImage(file='PowerRayLogo.png'))
    root.geometry("1235x820")
    root.minsize(1235, 820)

    if nPlatform == 1:
        user32 = ctypes.windll.user32
        user32.SetProcessDPIAware()
        myConfig.ScreenWidth = user32.GetSystemMetrics(0)
        myConfig.ScreenHeight = user32.GetSystemMetrics(1)
    root.attributes("-alpha", 00)
    root.state('zoomed')  # maximize the window
    myConfig.ScreenHeight = root.winfo_height()
    myConfig.ScreenWidth = root.winfo_width()
    root.state('normal')
    myConfig.RootX = myConfig.ScreenWidth/2 - (myConfig.RootWidth/2)
    myConfig.RootY = myConfig.ScreenHeight/2 - (myConfig.RootnHeight/2)
    root.geometry("%dx%d+%d+%d" % (myConfig.RootWidth,
                  myConfig.RootnHeight, myConfig.RootX, myConfig.RootY))
    root.attributes("-alpha", 1)

    # First block for IP Range frame
    if nPlatform == 1:
        frame1 = tk.LabelFrame(root, text="IP Range",
                               labelanchor="nw")
        frame1.place(x=10, y=5, height=180, width=400)
        varSelectAll = tk.IntVar()
        c1 = tk.Checkbutton(frame1, variable=varSelectAll, text='Select All',
                            onvalue=1, offvalue=0, command=checkSelectAll, width=30, anchor='w')
        c1.grid(column=0, row=0)

        btnPlus = tk.Button(frame1, text="+", width=5, command=onPlus)
        btnMinus = tk.Button(frame1, text='-', width=5, command=onMinus)
        btnScan = tk.Button(frame1, text="Scan", width=5,
                            pady=10, command=onScan)
        btnLoadIP = tk.Button(
            frame1, width=5, pady=3, wraplength=40, text="Load File", command=onLoadIPList)
        btnLoadIP.grid(row=2, column=1, padx=2)
        btnScanIP = tk.Button(
            frame1, width=5, pady=3, wraplength=40, text="Scan File", command=onScanList)
        btnScanIP.grid(row=2, column=2, padx=2)

        btnPlus.grid(row=0, column=1, padx=5)
        btnMinus.grid(row=0, column=2, padx=5)
        btnScan.grid(row=1, column=1, padx=5)

        listbox = tk.Listbox(frame1, height=6, width=30, fg="black",
                             activestyle='dotbox', font="Helvetica", bg="white", selectmode="extended")
    else:
        frame1 = tk.LabelFrame(root, text="IP Range",
                               labelanchor="nw")
        frame1.place(x=10, y=5, height=160, width=400)
        varSelectAll = tk.IntVar()
        c1 = tk.Checkbutton(frame1, variable=varSelectAll, text='Select All',
                            onvalue=1, offvalue=0, command=checkSelectAll, width=30, anchor='w')
        c1.grid(row=0, column=0)

        btnPlus = tk.Button(frame1, text="+", width=2, command=onPlus)
        btnMinus = tk.Button(frame1, text='-', width=2, command=onMinus)
        btnScan = tk.Button(frame1, text="Scan", width=2,
                            pady=10, command=onScan)
        btnLoadIP = tk.Button(
            frame1, width=2, pady=2, wraplength=40, text="Load File", command=onLoadIPList)
        btnLoadIP.grid(row=2, column=1, padx=2)
        btnScanIP = tk.Button(
            frame1, width=2, pady=2, wraplength=40, text="Scan File", command=onScanList)
        btnScanIP.grid(row=2, column=2, padx=2)

        btnPlus.grid(row=0, column=1)
        btnMinus.grid(row=0, column=2)
        btnScan.grid(row=1, column=1)

        listbox = tk.Listbox(frame1, height=6, width=30, fg="white",
                             activestyle='dotbox', font="Helvetica", bg="black", selectmode="extended")

    j = 1
    for i in myConfig.IPs:
        listbox.insert(j, i['From'] + ' ~ ' + i['To'])
        j += 1

    listbox.grid(row=1, column=0, rowspan=2, pady=5)
    listbox.bind('<<ListboxSelect>>', onSelect)

    # 2nd frame for pool configuration
    if nPlatform == 1:
        frame2 = tk.LabelFrame(
            root, text="Pool Configuration", labelanchor="nw")
        frame2.place(x=420, y=5, height=145, width=800)
    else:
        frame2 = tk.LabelFrame(
            root, text="Pool Configuration", labelanchor="nw")
        frame2.place(x=420, y=5, height=125, width=800)

    varChk21 = tk.IntVar()
    chk21 = tk.Checkbutton(frame2, variable=varChk21, text='Pool',
                           onvalue=1, offvalue=0, width=10, anchor='w')
    chk21.grid(row=0, column=0)
    varChk22 = tk.IntVar()
    chk22 = tk.Checkbutton(frame2, variable=varChk22, text='Wallet',
                           onvalue=1, offvalue=0, width=10, anchor='w')
    chk22.grid(row=1, column=0)
    varChk23 = tk.IntVar()
    chk23 = tk.Checkbutton(frame2, variable=varChk23, text='Password',
                           onvalue=1, offvalue=0, width=10, anchor='w')
    chk23.grid(row=2, column=0)

    OptionList21 = myConfig.Pool
    varOpt21 = tk.StringVar()
    varOpt21.set(OptionList21[0])
    opt21 = tk.OptionMenu(frame2, varOpt21, *OptionList21)
    if nPlatform == 1:
        opt21.config(width=45)
    else:
        opt21.config(width=35)
    opt21.config(anchor=tk.W)
    opt21.grid(row=0, column=1, sticky=tk.W)

    OptionList22 = myConfig.Wallet
    varOpt22 = tk.StringVar()
    varOpt22.set(OptionList22[0])
    opt22 = tk.OptionMenu(frame2, varOpt22, *OptionList22)
    if nPlatform == 1:
        opt22.config(width=45)
    else:
        opt22.config(width=35)
    opt22.config(anchor=tk.W)
    opt22.grid(row=1, column=1, sticky=tk.W)

    OptionList23 = myConfig.Password

    varOpt23 = tk.StringVar()
    varOpt23.set(OptionList23[0])
    opt23 = tk.OptionMenu(frame2, varOpt23, *OptionList23)
    if nPlatform == 1:
        opt23.config(width=10)
    else:
        opt23.config(width=5)
    opt23.config(anchor=tk.W)
    opt23.grid(row=2, column=1, sticky=tk.W)

    # Function to call ssh to IP with root and no password
    sshClient = paramiko.SSHClient()
    sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sshClient.set_log_channel("paramiko")
    sshPort = 22
    sshUsername = 'root'
    sshPassword = None
    strScriptsPath = "/root/scripts/ch/"

    def sshToWoker(strIP):
        strReturn = ""
        logger.info("ssh to IP=%s", strIP)  # 1.0.2
        bPowerRay = workerArray[dictIPtoIndex[strIP]].bPowerRay
        if bPowerRay == False:  # and nPlatform == 1:
            return None, strReturn

        NoAuthenticationMethodsAvailable = False

        try:
            sshClient.connect(strIP, sshPort,
                              sshUsername, sshPassword, timeout=float(varScanTimeout.get()), look_for_keys=False)
        except paramiko.SSHException as e:
            if str(e).find("No authentication") == 0:
                logger.info(e)
                NoAuthenticationMethodsAvailable = True
            else:
                logger.error(e)
                strException = str(e)
                if strException.find("Host key for server") >= 0:
                    strReturn = "Host key for server '192.168.88.99' does not match"
                    return None, strReturn
        except socket.timeout:
            logger.warning("Warning: ssh to %s timeout", strIP)
            workerArray[dictIPtoIndex[strIP]].bPowerRay = False
            workerArray[dictIPtoIndex[strIP]].FailCode = 2
            workerArray[dictIPtoIndex[strIP]
                        ].FailDesc = "ssh to " + strIP + " timeout"
            return None, strReturn
        except Exception as e:
            logger.error('paramiko.Exception = ', e)

        if NoAuthenticationMethodsAvailable:
            try:
                if not sshPassword:
                    sshClient.get_transport().auth_none(sshUsername)
                    return sshClient, ""
                else:
                    raise e
            except Exception as e:
                logger.error(e)
                return None, strReturn

        return sshClient, strReturn

    def sshToIP(strIP):  # 1.06
        strReturn = ""
        logger.info("ssh to IP=%s", strIP)
        NoAuthenticationMethodsAvailable = False
        try:
            sshClient.connect(strIP, sshPort,
                              sshUsername, sshPassword, timeout=float(varScanTimeout.get()), look_for_keys=False)
        except paramiko.SSHException as e:
            if str(e).find("No authentication") == 0:
                if myConfig.Verbose > 0:
                    logger.info(e)
                NoAuthenticationMethodsAvailable = True
            else:
                strReturn = "paramiko.SSHException: unknown"
                logger.error(strReturn)
                return None, strReturn
        except socket.timeout:
            strReturn = "ssh to " + strIP + " timeout"
            logger.error(strReturn)
            return None, strReturn
        except Exception as e:
            if myConfig.Verbose > 0:
                logger.error('paramiko.Exception = ', e)
            strReturn = "paramiko.Exception: unknown"
            logger.error(strReturn)
            return None, strReturn

        if NoAuthenticationMethodsAvailable:
            try:
                if not sshPassword:
                    sshClient.get_transport().auth_none(sshUsername)
                    return sshClient, ""
                else:
                    if myConfig.Verbose > 0:
                        logger.error(
                            'paramiko.SSHException (No authentication) = ', e)
                    strReturn = "unknown (No authentication)"
                    logger.error(strReturn)
                    return None, strReturn
            except Exception as e:
                logger.error(e)
                strReturn = "unknown (get_transport.auth_none)"
                logger.error(strReturn)
                return None, strReturn

        return sshClient, strReturn

    def ChangePoolConfiguration(PoolIP, changed21, changed22, changed23):
        arg1 = "\"'" + changed21 + "'\""
        arg2 = "\"'" + changed22 + "'\""
        arg3 = "\"'" + changed23 + "'\""
        client, strReturn = sshToWoker(PoolIP)
        if client == None:
            myIP = PoolIP
            workerArray[dictIPtoIndex[myIP]
                        ].FailDesc = "Can not ssh to " + myIP
            workerArray[dictIPtoIndex[myIP]].FailCode = 2
            return
        cmd = strScriptsPath + "setPoolConfiguration.sh " + arg1 + \
            " " + arg2 + " " + arg3
        stdin, stdout, stderr = client.exec_command(
            cmd)
        lines = stdout.readlines()
        for line in lines:
            print(line[:-1])
        errlines = stderr.readlines()
        for line in errlines:
            print(line[:-1])
        stderr.close()
        stdout.close()
        client.close()

    def onChangeAll():
        if varChk21.get() == 0 and varChk22.get() == 0 and varChk23.get() == 0:
            messagebox.showwarning(
                title="Warning", message="No checkbox selected.")
        else:
            if not messagebox.askokcancel("Confirm to change?", message="Do you confirm to change ALL items?"):
                return
            for item in tvWorker.get_children():
                item_text = tvWorker.item(item, "values")
                PoolIP = item_text[tvWorker['columns'].index("IP")]
                changed21 = ""
                changed22 = ""
                changed23 = ""
                if varChk21.get():
                    changed21 = varOpt21.get()
                    tvWorker.set(item, tvWorker['columns'].index(
                        "PoolAddress"), changed21)
                if varChk22.get():
                    changed22 = varOpt22.get()
                    tvWorker.set(item, tvWorker['columns'].index(
                        "WalletAddress"), changed22)
                if varChk23.get():
                    changed23 = varOpt23.get()
                    tvWorker.set(item, tvWorker['columns'].index(
                        "Password"), changed23)
                # Change the pool configuration on the select target IP address
                ChangePoolConfiguration(
                    PoolIP, changed21, changed22, changed23)

    def onChangeSelected():
        if len(tvWorker.selection()) == 0:
            messagebox.showwarning(
                title="Warning", message="You do not select any row.")
        elif varChk21.get() == 0 and varChk22.get() == 0 and varChk23.get() == 0:
            messagebox.showwarning(
                title="Warning", message="No checkbox selected.")
        else:
            if not messagebox.askokcancel("Confirm to change?", message="Do you confirm to change the selected items?"):
                return
            for item in tvWorker.selection():
                item_text = tvWorker.item(item, "values")
                PoolIP = item_text[tvWorker['columns'].index("IP")]
                changed21 = ""
                changed22 = ""
                changed23 = ""
                if varChk21.get():
                    changed21 = varOpt21.get()
                    tvWorker.set(item, tvWorker['columns'].index(
                        "PoolAddress"), changed21)
                if varChk22.get():
                    changed22 = varOpt22.get()
                    tvWorker.set(item, tvWorker['columns'].index(
                        "WalletAddress"), changed22)
                if varChk23.get():
                    changed23 = varOpt23.get()
                    tvWorker.set(item, tvWorker['columns'].index(
                        "Password"), changed23)
                # Change the pool configuration on the select target IP address
                ChangePoolConfiguration(
                    PoolIP, changed21, changed22, changed23)

    if nPlatform == 1:
        btnChangeAll = tk.Button(frame2, text="Change All",
                                 width=10, command=onChangeAll)
        btnChangeAll.grid(row=3, column=0, padx=10, sticky=tk.W)

        btnChangeSelected = tk.Button(
            frame2, text="Change Selected", width=13, command=onChangeSelected)
        btnChangeSelected.grid(row=3, column=1, ipadx=1, sticky=tk.W)
    else:
        btnChangeAll = tk.Button(frame2, text="Change All",
                                 width=7, command=onChangeAll)
        btnChangeAll.grid(row=3, column=0, sticky=tk.W)

        btnChangeSelected = tk.Button(
            frame2, text="Change Selected", width=10, command=onChangeSelected)
        btnChangeSelected.grid(row=3, column=1, sticky=tk.W)

    def onShow(index):
        tvWorker.column("#0", width=40,  stretch=False)
        for col in columns:  # 绑定函数，使表头可排序
            tvWorker.heading(col, text=col, command=lambda _col=col: treeview_sort_column(
                tvWorker, _col, False))
            width = 80
            minwidth = 60
            if col == "Model":
                width = 60
            if col == "IP":
                width = 120
            if col == "Worker":
                width = 120
            if col == "MAC":
                width = 130
            if col == "ServerID":
                width = 140
            if col == "PoolAddress":
                width = 300
            if col == "WalletAddress":
                width = 350
            if col == "FailDesc":
                width = 300
            if nPlatform == 1:
                if col == "Model":
                    width = 50
                if col == "IP":
                    width = 100
                if col == "Worker":
                    width = 100
                if col == "MAC":
                    width = 100
                if col == "ServerID":
                    width = 120
                if col == "Status":
                    width = 60
                if col == "PoolAddress":
                    width = 250
                if col == "WalletAddress":
                    width = 270
                if col == "SelfCalHashRate":
                    width = 120
                if col == "PoolHashRate":
                    width = 110
                if col == "WorkingAsic":
                    width = 100
                if col == "FAN1":
                    width = 50
                if col == "FAN2":
                    width = 50
                if col == "FAN3":
                    width = 50
                if col == "FAN4":
                    width = 50
                if col == "FAN5":
                    width = 50
                if col == "MinerOPFreq":
                    width = 110
                if col == "PowerConsumption":
                    width = 140
                if col == "DHCPorFixedIP":
                    width = 120
                if col == "BoardTemp1":
                    width = 100
                if col == "BoardTemp2":
                    width = 100
                if col == "BoardTemp3":
                    width = 100
                if col == "BoardTemp4":
                    width = 100
                if col == "BoardTemp5":
                    width = 100
                if col == "BoardTemp6":
                    width = 100
                if col == "BoardTemp7":
                    width = 100
                if col == "BoardTemp8":
                    width = 100
            if index == 0:
                if myConfig.ShowAll[col] == '0':
                    minwidth = 0
                    width = 0
            if index == 1:
                if myConfig.Show1[col] == '0':
                    minwidth = 0
                    width = 0
            if index == 2:
                if myConfig.Show2[col] == '0':
                    minwidth = 0
                    width = 0
            if index == 3:
                if myConfig.Show3[col] == '0':
                    minwidth = 0
                    width = 0
            if index == 4:
                if myConfig.Show4[col] == '0':
                    minwidth = 0
                    width = 0
            if index == 5:
                if myConfig.Show5[col] == '0':
                    minwidth = 0
                    width = 0
            tvWorker.column(col, minwidth=minwidth, width=width, stretch=False)

    def onShowAll():
        onShow(0)
        if myConfig.bScan:
            btnShowAll.config(fg="blue")
            btnShow1.config(fg="black")
            btnShow2.config(fg="black")
            btnShow3.config(fg="black")
            btnShow4.config(fg="black")
            btnShow5.config(fg="black")

    def onShow1():
        onShow(1)
        if myConfig.bScan:
            btnShowAll.config(fg="black")
            btnShow1.config(fg="blue")
            btnShow2.config(fg="black")
            btnShow3.config(fg="black")
            btnShow4.config(fg="black")
            btnShow5.config(fg="black")

    def onShow2():
        onShow(2)
        if myConfig.bScan:
            btnShowAll.config(fg="black")
            btnShow1.config(fg="black")
            btnShow2.config(fg="blue")
            btnShow3.config(fg="black")
            btnShow4.config(fg="black")
            btnShow5.config(fg="black")

    def onShow3():
        onShow(3)
        if myConfig.bScan:
            btnShowAll.config(fg="black")
            btnShow1.config(fg="black")
            btnShow2.config(fg="black")
            btnShow3.config(fg="blue")
            btnShow4.config(fg="black")
            btnShow5.config(fg="black")

    def onShow4():
        onShow(4)
        if myConfig.bScan:
            btnShowAll.config(fg="black")
            btnShow1.config(fg="black")
            btnShow2.config(fg="black")
            btnShow3.config(fg="black")
            btnShow4.config(fg="blue")
            btnShow5.config(fg="black")

    def onShow5():
        onShow(5)
        if myConfig.bScan:
            btnShowAll.config(fg="black")
            btnShow1.config(fg="black")
            btnShow2.config(fg="black")
            btnShow3.config(fg="black")
            btnShow4.config(fg="black")
            btnShow5.config(fg="blue")

    def onQuit():
        logger.info("=== End to of PowerRayETC ===")
        quit()

    if nPlatform == 1:
        btnShowAll = tk.Button(
            root, text="Show All", width=10, command=onShowAll)
        btnShowAll.place(x=420, y=155, height=30, width=100)

        btnShow1 = tk.Button(
            root, text="Show #1", width=10, command=onShow1)
        btnShow1.place(x=525, y=155, height=30, width=100)

        btnShow2 = tk.Button(
            root, text="Show #2", width=10, command=onShow2)
        btnShow2.place(x=630, y=155, height=30, width=100)

        btnShow3 = tk.Button(
            root, text="Show #3", width=10, command=onShow3)
        btnShow3.place(x=735, y=155, height=30, width=100)

        btnShow4 = tk.Button(
            root, text="Show #4", width=10, command=onShow4)
        btnShow4.place(x=840, y=155, height=30, width=100)

        btnShow5 = tk.Button(
            root, text="Show #5", width=10, command=onShow5)
        btnShow5.place(x=945, y=155, height=30, width=100)

        btnQuit = tk.Button(
            root, text="Quit Program", width=10, command=onQuit)
        btnQuit.place(x=1120, y=155, height=30, width=100)
    else:
        btnShowAll = tk.Button(
            root, text="Show All", width=10, command=onShowAll)
        btnShowAll.place(x=420, y=137, height=30, width=100)

        btnShow1 = tk.Button(
            root, text="Show #1", width=10, command=onShow1)
        btnShow1.place(x=520, y=137, height=30, width=100)

        btnShow2 = tk.Button(
            root, text="Show #2", width=10, command=onShow2)
        btnShow2.place(x=620, y=137, height=30, width=100)

        btnShow3 = tk.Button(
            root, text="Show #3", width=10, command=onShow3)
        btnShow3.place(x=720, y=137, height=30, width=100)

        btnShow4 = tk.Button(
            root, text="Show #4", width=10, command=onShow4)
        btnShow4.place(x=820, y=137, height=30, width=100)

        btnShow5 = tk.Button(
            root, text="Show #5", width=10, command=onShow5)
        btnShow5.place(x=920, y=137, height=30, width=100)

        btnQuit = tk.Button(
            root, text="Quit Program", width=10, command=onQuit)
        btnQuit.place(x=1120, y=137, height=30, width=100)

    # 3rd frame for scanning setting
    frame3 = tk.LabelFrame(root, text="Scanning Setting",
                           labelanchor="nw")
    if nPlatform == 1:
        frame3.place(x=10, y=185, height=105, width=400)
    else:
        frame3.place(x=10, y=170, height=105, width=400)

    lblScanTimeout = tk.Label(
        frame3, text="Scanning Timeout:")
    lblScanTimeout.grid(row=0, column=0, sticky=tk.E, ipadx=5)

    lblRefreshPeriod = tk.Label(
        frame3, text="Refresh Period:")
    lblRefreshPeriod.grid(row=1, column=0, sticky=tk.E, ipadx=5)

    def onConfirmChange():
        myConfig.Scanning = varScanTimeout.get()
        myConfig.Refresh = varRefreshPeriod.get()
        action.counter = int(myConfig.Refresh)*60
        logger.info("Change scan timeout = %d, refresh time in seconds = %d", int(
            myConfig.Scanning), int(myConfig.Refresh))

    varScanTimeout = tk.StringVar()
    varScanTimeout.set(myConfig.Scanning)
    entryScanTimeout = tk.Entry(
        frame3, textvariable=varScanTimeout, width=4)  # , commmand=onScanPeriod)
    entryScanTimeout.grid(row=0, column=1, padx=5, pady=5)

    varRefreshPeriod = tk.StringVar()
    varRefreshPeriod.set(myConfig.Refresh)
    entryRefreshPeriod = tk.Entry(
        frame3, textvariable=varRefreshPeriod, width=4)  # , command=onRefreshPeriod)
    entryRefreshPeriod.grid(row=1, column=1, padx=5, pady=5)

    lblSeconds = tk.Label(
        frame3, text="Second(s)")
    lblSeconds.grid(row=0, column=2, sticky=tk.W)

    lblMinites = tk.Label(
        frame3, text="Minute(s)")
    lblMinites.grid(row=1, column=2, sticky=tk.W)

    if nPlatform == 1:
        btnConfirm = tk.Button(frame3, text="Confirm Change", width=11,
                               command=onConfirmChange, padx=5)
        btnConfirm.grid(row=0, column=3, rowspan=2, ipadx=5, ipady=15)
    else:
        btnConfirm = tk.Button(frame3, text="Confirm Change", width=9,
                               command=onConfirmChange)
        btnConfirm.grid(row=0, column=3, rowspan=2, ipadx=5, ipady=15)

    def onRadioDHCP():
        varIPMode.set(0)
        ipaddr.config(state="disabled")
        netmask.config(state="disabled")
        gateway.config(state="disabled")
        dns.config(state="disabled")
        #    btnChangeIP.config(state="disabled")
        btnDNS8888.config(state="disable")

    def onRadioStatic():
        varIPMode.set(1)
        ipaddr.config(state="normal")
        netmask.config(state="normal")
        gateway.config(state="normal")
        dns.config(state="normal")
        btnChangeIP.config(state="normal")
        btnDNS8888.config(state="normal")

    # Change the DHCP to Static with insert IP/Netmask/Gateway/DNS
    def ChangeDhcpToStatic(i, IP, Netmask, Gateway, DNS):
        strIP = tvWorker.item(tvWorker.selection()[0], 'values')[
            tvWorker["column"].index("IP")]
        client, strReturn = sshToWoker(strIP)
        if client == None:
            myIP = strIP
            workerArray[dictIPtoIndex[myIP]
                        ].FailDesc = "Can not ssh to " + myIP
            workerArray[dictIPtoIndex[myIP]].FailCode = 2
            return
        cmd = strScriptsPath + "setDhcpIPStatic.sh " + \
            str(i) + " " + IP.get() + " " + Netmask.get() + \
            " " + Gateway.get() + " " + DNS.get()
        stdin, stdout, stderr = client.exec_command(cmd)
        lstLines[i] = lstLines[i].replace("'dhcp'", "'static'")
        lstLines.insert(i+1, "\toption ipaddr '" + IP.get() + "'")
        lstLines.insert(i+2, "\toption netmask '" + Netmask.get() + "'")
        lstLines.insert(i+3, "\toption gateway '" + Gateway.get() + "'")
        lstLines.insert(i+4, "\toption dns '" + DNS.get() + "'")
        item = tvWorker.selection()[0]
        tvWorker.set(item, tvWorker['columns'].index("IP"), IP.get())
        stdout.close()
        client.close()

    # Change the Static to Static with IP/Netmask/Gateway/DNS
    def ChangeStaticToStatic(i, IP, Netmask, Gateway, DNS):
        strIP = tvWorker.item(tvWorker.selection()[0], 'values')[
            tvWorker["column"].index("IP")]
        client, strReturn = sshToWoker(strIP)
        if client == None:
            myIP = strIP
            workerArray[dictIPtoIndex[myIP]
                        ].FailDesc = "Can not ssh to " + myIP
            workerArray[dictIPtoIndex[myIP]].FailCode = 2
            return
        cmd = strScriptsPath + "setStaticIPStatic.sh " + \
            str(i) + " " + IP.get() + " " + Netmask.get() + \
            " " + Gateway.get() + " " + DNS.get()
        stdin, stdout, stderr = client.exec_command(cmd)
        if lstLines[i+1].find('ipaddr') > 0 or lstLines[i+1].find('netmask') > 0 or lstLines[i+1].find('gateway') > 0 or lstLines[i+1].find('dns') > 0:
            del lstLines[i+1]
        if lstLines[i+1].find('ipaddr') > 0 or lstLines[i+1].find('netmask') > 0 or lstLines[i+1].find('gateway') > 0 or lstLines[i+1].find('dns') > 0:
            del lstLines[i+1]
        if lstLines[i+1].find('ipaddr') > 0 or lstLines[i+1].find('netmask') > 0 or lstLines[i+1].find('gateway') > 0 or lstLines[i+1].find('dns') > 0:
            del lstLines[i+1]
        if lstLines[i+1].find('ipaddr') > 0 or lstLines[i+1].find('netmask') > 0 or lstLines[i+1].find('gateway') > 0 or lstLines[i+1].find('dns') > 0:
            del lstLines[i+1]
        lstLines.insert(i+1, "\toption ipaddr '" + IP.get() + "'")
        lstLines.insert(i+2, "\toption netmask '" + Netmask.get() + "'")
        lstLines.insert(i+3, "\toption gateway '" + Gateway.get() + "'")
        lstLines.insert(i+4, "\toption dns '" + DNS.get() + "'")
        item = tvWorker.selection()[0]
        tvWorker.set(item, tvWorker['columns'].index("IP"), IP.get())
        stdout.close()
        client.close()

    # Change the Static to DHCP
    def ChangeStaticToDhcp(i, IP):
        client, strReturn = sshToWoker(IP.get())
        if client == None:
            myIP = IP.get()
            workerArray[dictIPtoIndex[myIP]
                        ].FailDesc = "Can not ssh to " + myIP
            workerArray[dictIPtoIndex[myIP]].FailCode = 2
            return
        cmd = strScriptsPath + "setStaticIPDhcp.sh " + \
            str(i) + " " + IP.get()
        stdin, stdout, stderr = client.exec_command(cmd)
        lstLines[i] = lstLines[i].replace("'static'", "'dhcp'")
        if lstLines[i+1].find('ipaddr') > 0 or lstLines[i+1].find('netmask') > 0 or lstLines[i+1].find('gateway') > 0 or lstLines[i+1].find('dns') > 0:
            del lstLines[i+1]
        if lstLines[i+1].find('ipaddr') > 0 or lstLines[i+1].find('netmask') > 0 or lstLines[i+1].find('gateway') > 0 or lstLines[i+1].find('dns') > 0:
            del lstLines[i+1]
        if lstLines[i+1].find('ipaddr') > 0 or lstLines[i+1].find('netmask') > 0 or lstLines[i+1].find('gateway') > 0 or lstLines[i+1].find('dns') > 0:
            del lstLines[i+1]
        if lstLines[i+1].find('ipaddr') > 0 or lstLines[i+1].find('netmask') > 0 or lstLines[i+1].find('gateway') > 0 or lstLines[i+1].find('dns') > 0:
            del lstLines[i+1]
        item = tvWorker.selection()[0]
        tvWorker.set(item, tvWorker['columns'].index("IP"), "DHCP")
        stdout.close()
        client.close()

    lstLines = []

    def onChangeIP():
        item = tvWorker.selection()[0]
        item_text = tvWorker.item(item, "values")
        PoolIP = item_text[tvWorker['columns'].index("IP")]
        if PoolIP == 'DHCP':
            messagebox.showwarning(
                title="Warning", message="The DHCP IP is unknown")
            return
        if len(tvWorker.selection()) != 1:
            messagebox.showwarning(
                title="Warning", message="Please double click one record to change IP.")
            return
        findLan = False
        iLan = 0
        for i in range(len(lstLines)):
            line = lstLines[i]
            if line.find("'lan'") >= 0:
                findLan = True
                iLan = i
            if i >= iLan + 5 and iLan > 0:
                break
            # varIPMode.get() == '1' for current mode is static IP
            # varIPMode.get() == '0' for current mode is DHCP IP
            if findLan and line.find("'dhcp'") >= 0:
                ipSource = 'dhcp'
                if varIPMode.get() == '1':  # dhcp to static
                    logger.info("ChangeDhcpToStatic")
                    ChangeDhcpToStatic(i, varIP, varNetmask,
                                       varGateway, varDNS)
                else:
                    logger.info("DHCP to DHCP")  # Do nothing
                break
            if findLan and line.find("'static'") >= 0:
                ipSource = 'static'
                if varIPMode.get() == '0':  # static to dhcp
                    logger.info("ChangeStaticToDhcp")
                    ChangeStaticToDhcp(i, varIP)
                else:
                    # change from static IP1 to IP2 if IP1 != IP2
                    logger.info("Static to Static")
                    ChangeStaticToStatic(
                        i, varIP, varNetmask, varGateway, varDNS)
                break

    def onDNS8888():
        varDNS.set("8.8.8.8")
        logger.info("Set DNS server to '8.8.8.8'")

    frame4 = tk.LabelFrame(root, text="IP Configuration",
                           labelanchor="nw")
    if nPlatform == 1:
        frame4.place(x=10, y=290, height=170, width=400)
    else:
        frame4.place(x=10, y=280, height=165, width=400)
    varIPMode = tk.StringVar()
    varIPMode.set(0)
    radioIPDHCP = tk.Radiobutton(frame4, text='DHCP',
                                 var=varIPMode, value=0, command=onRadioDHCP)
    radioIPDHCP.grid(column=0, row=0, sticky='w')
    radioIPStatic = tk.Radiobutton(frame4, text='Static',
                                   var=varIPMode, value=1, command=onRadioStatic)
    radioIPStatic.grid(column=1, row=0, sticky='w')
    lblIP = tk.Label(frame4, text="IP:")
    lblIP.grid(row=1, column=0, sticky='e', padx=5)
    lblNetmask = tk.Label(frame4, text="Netmask:")
    lblNetmask.grid(row=2, column=0, sticky='e', padx=5)
    lblGateway = tk.Label(frame4, text="Gateway:")
    lblGateway.grid(row=3, column=0, sticky='e', padx=5)
    lblDNS = tk.Label(frame4, text="DNS:")
    lblDNS.grid(row=4, column=0, sticky='e', padx=5)
    varIP = tk.StringVar()
    varIP.set("192.168.66.66")
    vcmd1 = root.register(validate)
    ipaddr = tk.Entry(frame4, textvariable=varIP, width=20,
                      validate='key', validatecommand=(vcmd1, '%P'), state="disabled")
    ipaddr.grid(row=1, column=1)

    varNetmask = tk.StringVar()
    varNetmask.set("255.255.255.0")
    vcmd1 = root.register(validate)
    netmask = tk.Entry(frame4, textvariable=varNetmask, width=20,
                       validate='key', validatecommand=(vcmd1, '%P'), state="disabled")
    netmask.grid(row=2, column=1)

    varGateway = tk.StringVar()
    varGateway.set("192.168.66.1")
    vcmd1 = root.register(validate)
    gateway = tk.Entry(frame4, textvariable=varGateway, width=20,
                       validate='key', validatecommand=(vcmd1, '%P'), state="disabled")
    gateway.grid(row=3, column=1)

    varDNS = tk.StringVar()
    varDNS.set("8.8.8.8")
    vcmd1 = root.register(validate)
    dns = tk.Entry(frame4, textvariable=varDNS, width=20,
                   validate='key', validatecommand=(vcmd1, '%P'), state="disabled")
    dns.grid(row=4, column=1)

    if nPlatform == 1:
        btnChangeIP = tk.Button(frame4, text="Change IP", width=15,
                                command=onChangeIP, state="disabled")
        btnChangeIP.grid(row=0, column=3, padx=10)

        btnDNS8888 = tk.Button(frame4, text="DNS=8.8.8.8", width=15,
                               command=onDNS8888, state="normal")
        btnDNS8888.grid(row=4, column=3, padx=10)
    else:
        btnChangeIP = tk.Button(frame4, text="Change IP",
                                command=onChangeIP, state="disabled")
        btnChangeIP.grid(row=0, column=3)

        btnDNS8888 = tk.Button(frame4, text="DNS=8.8.8.8",
                               command=onDNS8888, state="normal")
        btnDNS8888.grid(row=4, column=3)

    frame5 = tk.LabelFrame(root, text="Miner Configuration",
                           labelanchor="nw")

    if nPlatform == 1:
        frame5.place(x=10, y=460, height=55, width=400)
    else:
        frame5.place(x=10, y=450, height=55, width=400)
    lblClock = tk.Label(frame5, text="OSC Clock:")
    lblClock.grid(row=0, column=0, sticky='e', padx=5)

    OptionList3 = myConfig.Clock

    varOpt3 = tk.StringVar()

    varOpt3.set(OptionList3[1])
    opt3 = tk.OptionMenu(frame5, varOpt3, *OptionList3)
    opt3.config(anchor=tk.W)
    opt3.config(width=15)
    opt3.grid(row=0, column=1)

    def onChangeMC(osc_clock):
        if len(tvWorker.selection()) == 0:
            messagebox.showwarning(
                title="Warning", message="You do not select any row.")
        else:
            for item in tvWorker.selection():
                item_text = tvWorker.item(item, "values")
                PoolIP = item_text[tvWorker['columns'].index("IP")]
                # Change the OSC Clock for selected records
                client, strReturn = sshToWoker(PoolIP)
                if client == None:
                    myIP = PoolIP
                    workerArray[dictIPtoIndex[myIP]
                                ].FailDesc = "Can not ssh to " + myIP
                    workerArray[dictIPtoIndex[myIP]].FailCode = 2
                    return
                stdin, stdout, stderr = client.exec_command(
                    strScriptsPath + "setOSCClock.sh " + osc_clock)
                lines = stdout.readlines()
                nLen = len(lines)
                if nLen > 0:
                    for line in lines:
                        print(line[-1])
                if nLen > 2:
                    if lines[nLen-2] == "offline\n" and lines[nLen-1] == "reboot\n":
                        logger.info("Rebooting")
                        tvWorker.set(item, tvWorker['columns'].index(
                            "Status"), "Rebooting")
                stdout.close()
                client.close()

    btnChangeMC = tk.Button(frame5, text="Change Clock",
                            command=lambda: onChangeMC(varOpt3.get()))
    btnChangeMC.grid(row=0, column=2, sticky=tk.W)

    frame61 = tk.LabelFrame(root, text="Miner Control", labelanchor="nw")
    if nPlatform == 1:
        frame61.place(x=10, y=520, height=290, width=130)
    else:
        frame61.place(x=10, y=510, height=285, width=130)

    def onStart():
        if len(tvWorker.selection()) == 0:
            messagebox.showwarning(
                title="Warning", message="You do not select any miner.")
        else:
            for item in tvWorker.selection():
                item_text = tvWorker.item(item, "values")
                PoolIP = item_text[tvWorker['columns'].index("IP")]
                # Stop the cgminer until no cgminer process in the ps or ps aux
                client, strReturn = sshToWoker(PoolIP)
                if client == None:
                    myIP = PoolIP
                    workerArray[dictIPtoIndex[myIP]
                                ].FailDesc = "Can not ssh to " + myIP
                    workerArray[dictIPtoIndex[myIP]].FailCode = 2
                    return
                stdin, stdout, stderr = client.exec_command(
                    strScriptsPath + "onStart.sh")
                lines = stdout.readlines()
                for line in lines:
                    # print(line[0:-1])
                    if line.find("Mining") >= 0:
                        strNewStatus = line[0:-1]
                        # item = tvWorker.selection()[0]
                        tvWorker.set(item, tvWorker['columns'].index(
                            "Status"), strNewStatus)
                stdout.close()
                client.close()

    def onStop():
        if len(tvWorker.selection()) == 0:
            messagebox.showwarning(
                title="Warning", message="You do not select any miner.")
        else:
            logger.info("======== Press onStop button()")
            for item in tvWorker.selection():
                item_text = tvWorker.item(item, "values")
                PoolIP = item_text[tvWorker['columns'].index("IP")]
                # Stop the cgminer until no cgminer process in the ps or ps aux
                client, strReturn = sshToWoker(PoolIP)
                if client == None:
                    myIP = PoolIP
                    workerArray[dictIPtoIndex[myIP]
                                ].FailDesc = "Can not ssh to " + myIP
                    workerArray[dictIPtoIndex[myIP]].FailCode = 2
                    return
                stdin, stdout, stderr = client.exec_command(
                    strScriptsPath + "onStop.sh " + str(myConfig.StopTimeout))
                lines = stdout.readlines()
                for line in lines:
                    # print(line[0:-1])
                    if line.find("offline") >= 0:
                        strNewStatus = line[0:-1]
                        # item = tvWorker.selection()[0]
                        tvWorker.set(item, tvWorker['columns'].index(
                            "Status"), strNewStatus)
                stdout.close()
                client.close()

    def onReboot():
        if len(tvWorker.selection()) == 0:
            messagebox.showwarning(
                title="Warning", message="You do not select any miner.")
        else:
            for item in tvWorker.selection():
                item_text = tvWorker.item(item, "values")
                PoolIP = item_text[tvWorker['columns'].index("IP")]
                strStatus = item_text[tvWorker['columns'].index("Status")]
                # Stop the cgminer until no cgminer process in the ps or ps aux
                client, strReturn = sshToWoker(PoolIP)
                if client == None:
                    myIP = PoolIP
                    workerArray[dictIPtoIndex[myIP]
                                ].FailDesc = "Can not ssh to " + myIP
                    workerArray[dictIPtoIndex[myIP]].FailCode = 2
                    return
                cmd = strScriptsPath + "onReboot.sh " + \
                    str(myConfig.StopTimeout)
                stdin, stdout, stderr = client.exec_command(cmd)
                lines = stdout.readlines()
                if lines[0] == "offline\n" and lines[1] == "reboot\n":
                    logger.info("Rebooting")
                    tvWorker.set(item, tvWorker['columns'].index(
                        "Status"), "Rebooting")
                stdout.close()
                client.close()

    def onLoadDefault():
        if len(tvWorker.selection()) == 0:
            messagebox.showwarning(
                title="Warning", message="You do not select any miner.")
        else:
            for item in tvWorker.selection():
                item_text = tvWorker.item(item, "values")
                PoolIP = item_text[tvWorker['columns'].index("IP")]
                strStatus = item_text[tvWorker['columns'].index("Status")]
                # Stop the cgminer until no cgminer process in the ps or ps aux
                client, strReturn = sshToWoker(PoolIP)
                if client == None:
                    myIP = PoolIP
                    workerArray[dictIPtoIndex[myIP]
                                ].FailDesc = "Can not ssh to " + myIP
                    workerArray[dictIPtoIndex[myIP]].FailCode = 2
                    return
                stdin, stdout, stderr = client.exec_command(
                    strScriptsPath + "LoadDefault.sh")
                logger.info("Load Default and then reboot")
                item = tvWorker.selection()[0]
                tvWorker.set(item, tvWorker['columns'].index(
                    "Status"), "LoadDefault")
                stdout.close()
                client.close()

    def onFindOn():
        if len(tvWorker.selection()) == 0:
            messagebox.showwarning(
                title="Warning", message="You do not select any miner.")
        else:
            for item in tvWorker.selection():
                item_text = tvWorker.item(item, "values")
                PoolIP = item_text[tvWorker['columns'].index("IP")]
                # Turn the LED on
                client, strReturn = sshToWoker(PoolIP)
                if client == None:
                    myIP = PoolIP
                    workerArray[dictIPtoIndex[myIP]
                                ].FailDesc = "Can not ssh to " + myIP
                    workerArray[dictIPtoIndex[myIP]].FailCode = 2
                    return
                stdin, stdout, stderr = client.exec_command(
                    strScriptsPath + "onSearchOn.sh")
                logger.info("Flash LED of the worker")
                stdout.close()
                client.close()

    def onFindOff():
        if len(tvWorker.selection()) == 0:
            messagebox.showwarning(
                title="Warning", message="You do not select any worker.")
        else:
            for item in tvWorker.selection():
                item_text = tvWorker.item(item, "values")
                PoolIP = item_text[tvWorker['columns'].index("IP")]
                # Turn the LED on
                client, strReturn = sshToWoker(PoolIP)
                if client == None:
                    myIP = PoolIP
                    workerArray[dictIPtoIndex[myIP]
                                ].FailDesc = "Can not ssh to " + myIP
                    workerArray[dictIPtoIndex[myIP]].FailCode = 2
                    return
                stdin, stdout, stderr = client.exec_command(
                    strScriptsPath + "onSearchOff.sh")
                logger.info("Turn off the LEDs of worker")
                stdout.close()
                client.close()

    if nPlatform == 1:
        myPadx = 20
        myWidth = 12
        btnStart = tk.Button(frame61, text="Start",
                             width=myWidth, command=onStart)
        btnStart.grid(row=0, column=0, padx=myPadx, pady=1)
        btnStop = tk.Button(frame61, text="Stop",
                            width=myWidth, command=onStop)
        btnStop.grid(row=1, column=0, padx=myPadx, pady=1)
        btnReboot = tk.Button(frame61, text="Reboot",
                              width=myWidth, command=onReboot)
        btnReboot.grid(row=2, column=0, padx=myPadx, pady=1)
        btnFind = tk.Button(frame61, text="Find (LED ON)",
                            width=myWidth, command=onFindOn)
        btnFind.grid(row=3, column=0, padx=myPadx, pady=1)
        btnFindOff = tk.Button(
            frame61, text="Find (LED OFF)", width=myWidth, command=onFindOff)
        btnFindOff.grid(row=4, column=0, padx=myPadx, pady=1)
        btnFReset = tk.Button(frame61, text="Load Default",
                              width=myWidth, command=onLoadDefault)
        btnFReset.grid(row=5, column=0, padx=myPadx, pady=1)
    else:
        myPadx = 9
        btnStart = tk.Button(frame61, text="Start", width=8, command=onStart)
        btnStart.grid(row=0, column=0, padx=myPadx)
        btnStop = tk.Button(frame61, text="Stop", width=8, command=onStop)
        btnStop.grid(row=1, column=0, padx=myPadx)
        btnReboot = tk.Button(frame61, text="Reboot",
                              width=8, command=onReboot)
        btnReboot.grid(row=2, column=0, padx=myPadx)
        btnFind = tk.Button(frame61, text="Find (LED ON)",
                            width=8, command=onFindOn)
        btnFind.grid(row=3, column=0, padx=myPadx)
        btnFindOff = tk.Button(
            frame61, text="Find (LED OFF)", width=8, command=onFindOff)
        btnFindOff.grid(row=4, column=0, padx=myPadx)
        btnFReset = tk.Button(frame61, text="Load Default",
                              width=8, command=onLoadDefault)
        btnFReset.grid(row=5, column=0, padx=myPadx)

    varhr1 = tk.StringVar()
    varhr1.set(0)
    varmin1 = tk.StringVar()
    varmin1.set(0)
    varhr2 = tk.StringVar()
    varhr2.set(0)
    varmin2 = tk.StringVar()
    varmin2.set(0)

    def onCopy1():
        onCopy(1)

    def onCopy2():
        onCopy(2)

    def onCopy3():
        onCopy(3)

    def onCopy(nCopy):
        global varhr1
        global varhr2
        global varmin1
        global varmin2
        if nCopy < 3 and len(tvWorker.get_children()) == 0:
            messagebox.showwarning(
                title="Warning", message="No data in the tree view.")
            return
        if nCopy == 1 and len(tvWorker.selection()) == 0:
            messagebox.showwarning(
                title="Warning", message="Please double click one miner to copy log.")
            return
        if nCopy == 2 and len(tvWorker.selection()) == 0:
            messagebox.showwarning(
                title="Warning", message="Please select at least one miner to copy log.")
            return
        lstServerID = []
        if nCopy == 1 or nCopy == 2:
            for item in tvWorker.selection():
                item_text = tvWorker.item(item, "values")
                if varServerMode.get() == '0':
                    lstServerID.append(
                        item_text[tvWorker['columns'].index("ServerID")])
                else:
                    lstServerID.append(
                        item_text[tvWorker['columns'].index("MAC")])
        elif nCopy == 3:
            for item in tvWorker.get_children():
                item_text = tvWorker.item(item, "values")
                if varServerMode.get() == '0':
                    lstServerID.append(
                        item_text[tvWorker['columns'].index("ServerID")])
                else:
                    lstServerID.append(
                        item_text[tvWorker['columns'].index("MAC")])

        conn = ConnectToDB()
        cursor = GetCursorDB(conn)
        d2_tmp = datetime.strptime(varD2.get(), '%Y-%m-%d')
        d2hm_tmp = d2_tmp.replace(
            hour=int(varhr2.get()), minute=int(varmin2.get()))
        d2hm_str = d2hm_tmp.strftime('%Y-%m-%d %H:%M')
        d1_tmp = datetime.strptime(varD1.get(), '%Y-%m-%d')
        d1hm_tmp = d1_tmp.replace(
            hour=int(varhr1.get()), minute=int(varmin1.get()))
        d1hm_str = d1hm_tmp.strftime('%Y-%m-%d %H:%M')
        WriteWorkerToFile(cursor, d1hm_str, d2hm_str, lstServerID, nCopy)
        CloseDB(conn, cursor)

    def onChanePR8XFAN():
        if action.scan:  # if action.scan == True. The onScan will not running. Default action.scan is False.
            messagebox.showwarning(
                title="Another scan is running", message="Another scan is running")
            return
        action.scan = True
        i = 0
        onShow5()
        onScanT0 = datetime.now()
        filename = filedialog.askopenfilename(initialdir="./",
                                              title="Select a single column IPv4 text file",
                                              filetypes=(("Text files",
                                                          "*.txt"),
                                                         ("all files",
                                                         "*.*")))
        if filename == '':
            messagebox.showwarning(
                title="Warning", message="You do not select any file")
            action.scan = False
            return

        handleFile = open(filename, "r")
        tvWorker.delete(*tvWorker.get_children())

        for line in handleFile:
            myIP = line.strip()
            myIPs.append(myIP)
            FailCode = ""
            FailDesc = ""
            if myConfig.Verbose:
                logger.debug("%02d: Load IP=%s from file %s",
                             i, myIP, filename)

            client, strReturn = sshToIP(myIP)

            if client == None:
                if strReturn.find("unknown") >= 0:
                    FailCode = 99
                    FailDesc = strReturn
                else:
                    FailCode = 5
                    FailDesc = strReturn
                tvWorker.insert("", tk.END, text=str(i+1),
                                values=("", myIP, "Fan% set to "+varOptPr8XFan.get()+"%", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", FailCode, FailDesc), tag="yellow")
                i += 1
                continue

            try:
                stdin, stdout, stderr = client.exec_command(
                    "rm -rf " + strScriptsPath + "; mkdir -p " + strScriptsPath)
                logger.info(
                    "Delete %s and re-created on the worker.", strScriptsPath)
                stderr.close()
                stdout.close()
            except Exception as e:
                logger.error(e)
                FailCode = 6
                FailDesc = myIP + " exec command fail"
                stderr.close()
                stdout.close()
                client.close()
                tvWorker.insert("", tk.END, text=str(i+1),
                                values=("", myIP, "Fan% set to "+varOptPr8XFan.get()+"%", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", FailCode, FailDesc), tag="red")
                i += 1
                continue
            a = "\\"
            filename = "C:\\Users\\" + os.getlogin() + a + "ch\\scripts\\ch\\?etFanSpeed.sh"
            logger.info(
                "Copy '%s' to IP=%s", str(filename), myIP)
            cmd1 = "scp -p -C -r -4 " + str(filename) + " root@" + \
                myIP + ":/root/scripts/ch"
            ret = subprocess.run(cmd1, shell=True, stdout=subprocess.PIPE,
                                 stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info("Run '%s'", cmd1)

            filename = "C:\\Users\\" + os.getlogin() + a + "ch\\scripts\\ch\\*.py"
            logger.info(
                "Copy '%s' to IP=%s", str(filename), myIP)
            cmd1 = "scp -p -C -r -4 " + str(filename) + " root@" + \
                myIP + ":/root/scripts/ch"
            ret = subprocess.run(cmd1, shell=True, stdout=subprocess.PIPE,
                                 stdin=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info("Run '%s'", cmd1)

            cmd2 = "chmod +x " + strScriptsPath + "*.sh"
            stdin, stdout, stderr = client.exec_command(cmd2)
            logger.info("Run '%s'", cmd2)
            lines = stdout.readlines()
            for line in lines:
                logger.info(line[:-1])
            errlines = stderr.readlines()
            for line in errlines:
                logger.error(line[:-1])
            stderr.close()
            stdout.close()

            cmd3 = strScriptsPath + "setFanSpeed.sh " + varOptPr8XFan.get()
            stdin, stdout, stderr = client.exec_command(cmd3)
            logger.info("Run '%s'", cmd3)
            lines = stdout.readlines()
            for line in lines:
                logger.info(line[:-1])
                if line.find("offline") >= 0:
                    logger.info("%s offline", myIP)
            errlines = stderr.readlines()
            for line in errlines:
                logger.error(line[:-1])
            stderr.close()
            stdout.close()
            client.close()
            tvWorker.insert("", tk.END, text=str(i+1),
                            values=("", myIP, "Fan% set to "+varOptPr8XFan.get()+"%", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                    "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""), tag="white")

            i += 1
        handleFile.close()
        onScanT1 = datetime.now()
        diff = onScanT1 - onScanT0
        logger.info("It takes %d seconds to load the %d records of IPv4 to set fan speed",
                    int(diff.total_seconds()), i)
        action.scan = False

    frame62 = tk.LabelFrame(
        root, text="Export log and change PR_8X fan duty", labelanchor="nw")
    if nPlatform == 1:
        frame62.place(x=150, y=520, height=290, width=260)
    else:
        frame62.place(x=150, y=510, height=285, width=260)

    d2 = datetime.now() + timedelta(1)
    d1 = d2 - timedelta(days=5)
    varD2 = tk.StringVar()
    varD1 = tk.StringVar()
    varServerID = tk.StringVar()
    varServerID.set("")

    if nPlatform == 1:
        mypady = 4
        mywidth = 3
        btnCopyAll = tk.Button(frame62, text="Export Time Between:",
                               command=onCopy3, width=23)
        btnCopyAll.grid(row=0, column=0, columnspan=2)
        lblcal1 = tk.Label(frame62, text="From:", width=3,
                           anchor="e", padx=5, pady=mypady)
        lblcal1.grid(row=1, column=0, ipadx=5)
        lblcal2 = tk.Label(frame62, text="To:", width=3,
                           anchor="e", padx=5, pady=mypady)
        lblcal2.grid(row=2, column=0, ipadx=5)
        cal1 = DateEntry(frame62, setmode='day',
                         date_pattern='yyyy-MM-dd', year=d1.year, month=d1.month, day=d1.day,
                         background="white", disabledbackground="gray", bordercolor="white",
                         headersbackground="white", normalbackground="white", foreground='black',
                         normalforeground='blue', headersforeground='black', anchor="e", textvariable=varD1, width=15, padx=5, pady=mypady)
        cal1.grid(row=1, column=1, padx=5)
        cal2 = DateEntry(frame62, setmode='day',
                         date_pattern='yyyy-MM-dd', year=d2.year, month=d2.month, day=d2.day,
                         background="white", disabledbackground="gray", bordercolor="white",
                         headersbackground="white", normalbackground="white", foreground='black',
                         normalforeground='blue', headersforeground='black', anchor="e", textvariable=varD2, width=15, padx=5, pady=mypady)
        cal2.grid(row=2, column=1, padx=5)
        hr1 = tk.Spinbox(frame62, textvariable=varhr1, width=mywidth, from_=0, to=23,
                         fg="black", bg='white').grid(row=1, column=2)
        min1 = tk.Spinbox(frame62, text=varmin1, width=mywidth, from_=0, to=59,
                          fg="black", bg='white').grid(row=1, column=4)
        hr2 = tk.Spinbox(frame62, textvariable=varhr2, width=mywidth, from_=0, to=23,
                         fg="black", bg='white').grid(row=2, column=2)
        min2 = tk.Spinbox(frame62, text=varmin2, width=mywidth, from_=0, to=59,
                          fg="black", bg='white').grid(row=2, column=4)

        btnCopySelected = tk.Button(frame62, text="Export Selected Workers",
                                    command=onCopy2, width=23)
        btnCopySelected.grid(row=3, column=0, columnspan=2, pady=10)

        btnCopy = tk.Button(frame62, text="Export ServerID =",
                            command=onCopy1, width=23)
        btnCopy.grid(row=4, column=0, columnspan=2)
        ServerID = tk.Entry(
            frame62, textvariable=varServerID, width=24, justify=tk.CENTER)
        ServerID.grid(row=5, column=0, columnspan=2)
    else:
        mywidth = 2
        btnCopyAll = tk.Button(frame62, text="Export Time between:",
                               command=onCopy3, width=14)
        btnCopyAll.grid(row=0, column=0, columnspan=2)
        lblcal1 = tk.Label(frame62, text="From", width=3, anchor="w")
        lblcal1.grid(row=1, column=0)
        lblcal2 = tk.Label(frame62, text="To", width=3, anchor="w")
        lblcal2.grid(row=2, column=0)
        cal1 = DateEntry(frame62, selectmode='day',
                         date_pattern='yyyy-MM-dd', year=d1.year, month=d1.month, day=d1.day,
                         background="green", disabledbackground="gray", bordercolor="white",
                         headersbackground="white", normalbackground="white", foreground='black',
                         normalforeground='blue', headersforeground='black', anchor="e", textvariable=varD1)
        cal1.grid(row=1, column=1)
        cal2 = DateEntry(frame62, selectmode='day',
                         date_pattern='yyyy-MM-dd', year=d2.year, month=d2.month, day=d2.day,
                         background="green", disabledbackground="gray", bordercolor="white",
                         headersbackground="white", normalbackground="white", foreground='black',
                         normalforeground='blue', headersforeground='black', anchor="e", textvariable=varD2)
        cal2.grid(row=2, column=1)
        hr1 = tk.Spinbox(frame62, textvariable=varhr1, width=mywidth, from_=0, to=23,
                         fg="black", bg='white').grid(row=1, column=2)
        min1 = tk.Spinbox(frame62, text=varmin1, width=mywidth, from_=0, to=59,
                          fg="black", bg='white').grid(row=1, column=4)
        hr2 = tk.Spinbox(frame62, textvariable=varhr2, width=mywidth, from_=0, to=23,
                         fg="black", bg='white').grid(row=2, column=2)
        min2 = tk.Spinbox(frame62, text=varmin2, width=mywidth, from_=0, to=59,
                          fg="black", bg='white').grid(row=2, column=4)

        btnCopySelected = tk.Button(frame62, text="Export Selected Workers",
                                    command=onCopy2, width=14)
        btnCopySelected.grid(row=3, column=0, columnspan=2, pady=10)

        btnCopy = tk.Button(frame62, text="Export ServerID =",
                            width=14, command=onCopy1)
        btnCopy.grid(row=4, column=0, columnspan=2)
        ServerID = tk.Entry(
            frame62, textvariable=varServerID, width=17, justify=tk.CENTER)
        ServerID.grid(row=5, column=0, columnspan=2)

    if nPlatform == 1:
        lblPr8XFan = tk.Label(frame62, text="PR_8X Fan Duty(%)", width=23)
        lblPr8XFan.grid(row=6, column=0, columnspan=2)
        OptionListPr8xFanDuty = myConfig.pr_8x_fan_duty
        varOptPr8XFan = tk.StringVar()
        varOptPr8XFan.set(OptionListPr8xFanDuty[3])
        Opt621 = tk.OptionMenu(frame62, varOptPr8XFan, *OptionListPr8xFanDuty)
        Opt621.config(width=18)
        Opt621.grid(row=7, column=0, columnspan=2)
        btnPr8XFan = tk.Button(frame62, text="Change Fan Duty",
                               command=onChanePR8XFAN, width=23)
        btnPr8XFan.grid(row=8, column=0, columnspan=2)
    else:
        lblPr8XFan = tk.Label(frame62, text="PR_8X Fan Duty(%)", width=14)
        lblPr8XFan.grid(row=6, column=0, columnspan=2)
        OptionListPr8xFanDuty = myConfig.pr_8x_fan_duty
        varOptPr8XFan = tk.StringVar()
        varOptPr8XFan.set(OptionListPr8xFanDuty[3])
        Opt621 = tk.OptionMenu(frame62, varOptPr8XFan, *OptionListPr8xFanDuty)
        Opt621.config(width=12)
        Opt621.grid(row=7, column=0, columnspan=2)
        btnPr8XFan = tk.Button(frame62, text="Change Fan Duty",
                               command=onChanePR8XFAN, width=14)
        btnPr8XFan.grid(row=8, column=0, columnspan=2)

    def onServerID():
        varServerMode.set(0)  # ServerID
        btnCopy.config(text="Export ServerID =")

    def onMAC():
        varServerMode.set(1)  # MAC Address
        btnCopy.config(text="Export MAC Addr =")

    varServerMode = tk.StringVar()
    varServerMode.set(0)
    radioServerID = tk.Radiobutton(frame62, text='ServerID',
                                   var=varServerMode, value=0, command=onServerID)
    radioServerID.grid(row=4, column=2, columnspan=3, sticky='w')
    radioMACAddress = tk.Radiobutton(frame62, text='MAC',
                                     var=varServerMode, value=1, command=onMAC)
    radioMACAddress.grid(row=5, column=2, columnspan=3, sticky='w')

    frame7 = tk.LabelFrame(root, text="Miner List",
                           labelanchor="nw")
    if nPlatform == 1:
        frame7.place(x=420, y=185, height=625, width=800)
    else:
        frame7.place(x=420, y=170, height=625, width=800)

    Style = ttk.Style()
    Style.theme_use('clam')
    Style.configure("Treeview.Heading", background="light gray", foreground="black", font=(
        "Arial Bold", 11))
    if nPlatform == 1:
        nFontSize = 8
    else:
        nFontSize = 11
    Style.configure("Treeview", font=("Arial", nFontSize), anchor=LEFT)

    # init a scrollbar
    sbx = tk.Scrollbar(frame7, orient=tk.HORIZONTAL)
    sby = tk.Scrollbar(frame7, orient=tk.VERTICAL)
    # 預設是 show="tree"顯示圖標欄， "show=headings" 不顯示圖標欄。
    tvWorker = ttk.Treeview(
        frame7, height=18, show="headings", columns=columns)
    tvWorker.place(relx=0.01, rely=0.01, height=568, width=757)
    #tvWorker.place(relx=0.01, rely=0.01, height=frame7.winfo_height() - 57, width=frame7.winfo_width() - 45)

    tvWorker.configure(yscrollcommand=sby.set, xscrollcommand=sbx.set)
    # selectmode=BROWSE，一次選擇一項，預設。selectmode=EXTENDED，次選擇多項。selectmode=NONE，無法用滑鼠執行選擇。
    tvWorker.configure(selectmode="extended")

    sby.configure(command=tvWorker.yview)
    sbx.configure(command=tvWorker.xview)

    sby.place(relx=0.965, rely=0.01, width=22, height=595)
    sbx.place(relx=0.01, rely=0.955, width=757, height=22)
    #sby.place(relx=1-28/frame7.winfo_width(), rely=0.01, width=22, height=frame7.winfo_height() - 32)
    #sbx.place(relx=0.01, rely=1-30/frame7.winfo_height(), width=frame7.winfo_width() - 45, height=22)

    tvWorker.heading("#0", text="ID", anchor="center")
    for i in range(len(columns)):
        tvWorker.heading("#"+str(i+1), text=columns[i], anchor="center")
    tvWorker['show'] = 'tree headings'

    tvWorker.tag_configure('red', background='red')
    tvWorker.tag_configure('yellow', background='yellow')
    tvWorker.tag_configure('green', background='lightgreen')
    tvWorker.tag_configure('normal', background='white')
    tvWorker.tag_configure('gray', background='gray')

    '''
    myTag = 'normal'
    for i in range(100):
        if myTag == 'normal':
            myTag = 'red'
        elif myTag == 'red':
            myTag = 'yellow'
        elif myTag == 'yellow':
            myTag = 'green'
        else:
            myTag = 'normal'
        tvWorker.insert("", tk.END, text=str(i+1),
                        values=("PR_SB", "192.168.66.3", "192-168-66-3", "68:5E:6B:A0:10:34", "E2BCAA2238001403", "Mining", "NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA", 322.9, "NA", 2, "NA",
                        "NA", "NA", "NA", "NA", "stratum+tcp://asia1-etc.ethermine.org:4444", "0x57fc699ad1249f65759e1af273e26350dece1eb6", "NA", 1234, 19.5, "NA", "NA", 44.0, 40.0, "NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA"), tag=myTag)
    '''

    root.bind("<Configure>", resize)

    def onDClick(evt):
        w = evt.widget
        if len(w.selection()) == 0:
            return
        for item in w.selection():
            strIP = w.item(item)['values'][1]
            break

        if not strIP in dictIPtoIndex:
            bPowerRay = False
            return None
        else:
            bPowerRay = workerArray[dictIPtoIndex[strIP]].bPowerRay
            if bPowerRay == False and nPlatform == 1:
                return None

        client = None
        try:
            client, strReturn = sshToWoker(strIP)
        except paramiko.AuthenticationException as e:
            logger.info("Warning: ssh to %s authentication failed", strIP)
        if client == None:
            return
        elif client.get_transport().authenticated == False:
            client.close()
            return
        stdin, stdout, stderr = client.exec_command(
            strScriptsPath + "getIPnOSC.sh ;" + strScriptsPath + "getServerID.sh")
        lines = stdout.readlines()
        strProtocol = lines[0][:-1]
        strNetmask = lines[2][:-1]
        strGateway = lines[3][:-1]
        strDNS = lines[4][:-1]
        strOSCClock = lines[5][:-1]
        varOpt3.set(strOSCClock[1:-1])
        if varServerMode.get() == '0':
            if (len(lines) > 6):
                strServerID = lines[6][:-1]
                varServerID.set(strServerID)
        else:
            varServerID.set(workerArray[dictIPtoIndex[strIP]].MAC)

        varIP.set(strIP)
        varNetmask.set(strNetmask)
        varGateway.set(strGateway)
        varDNS.set(strDNS)
        if (strProtocol == 'dhcp'):
            varIPMode.set(0)
        else:
            varIPMode.set(1)
        nIPMode = varIPMode.get()
        if nIPMode == '0':
            ipaddr.config(state="disabled")
            netmask.config(state="disabled")
            gateway.config(state="disabled")
            dns.config(state="disabled")
        #    btnChangeIP.config(state="disabled")
        else:
            ipaddr.config(state="normal")
            netmask.config(state="normal")
            gateway.config(state="normal")
            dns.config(state="normal")
            btnChangeIP.config(state="normal")

        stdin, stdout, stderr = client.exec_command(
            "cat /etc/config/network")
        lines = stdout.readlines()
        lstLines.clear()
        for line in lines:
            line = line[0:-1]
            lstLines.append(line)
        stdout.close()
        client.close()

    tvWorker.bind('<Double-1>', onDClick)
    onShowAll()

    def treeview_sort_column(tv, col, reverse):  # Treeview、列名、排列方式
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        l.sort(reverse=reverse)  # 排序方式
        # rearrange items in sorted positions
        for index, (val, k) in enumerate(l):  # 根据排序后索引移动
            tv.move(k, '', index)
        tv.heading(col, command=lambda: treeview_sort_column(
            tv, col, not reverse))  # 重写标题，使之成为再点倒序的标题

    def ConnectToDB():
        conn = MySQLdb.connect(
            host=myConfig.mysqlHost,
            port=myConfig.mysqlPort,
            user=myConfig.mysqlUser,
            passwd=myConfig.mysqlPassword,
            db=myConfig.mysqlDatabase,
        )
        return conn

    def GetBatchID(cur):
        # cur = conn.cursor()
        cur.execute(
            "INSERT INTO batch (id, datetime) VALUES(DEFAULT, DEFAULT);")
        cur.execute("SELECT * FROM batch ORDER BY id DESC LIMIT 1;")
        for batch in cur:
            logger.info("The batch id=%d, datetime=%s and try to write %d of workers into scan table.",
                        batch[0], batch[1].strftime("%Y-%m-%d %H:%M:%S"), len(workerArray))
        return batch

    def WriteWorkerToFile(cur, d1, d2, lstServerIDs, nCopy):
        lenTotal = len(lstServerIDs)
        len1 = 0
        strServerIDs = "("
        for strServerID in lstServerIDs:
            strServerIDs = strServerIDs + "'" + strServerID + "'"
            len1 += 1
            if len1 < lenTotal:
                strServerIDs = strServerIDs + ","
            else:
                strServerIDs = strServerIDs + ")"
        if nCopy == 3:
            cmd = "select * from scan " \
                "where datetime >= '" + d1 + "' and datetime < '" + \
                d2 + "';"
        else:
            if varServerMode.get() == '0':
                cmd = "select * from scan " \
                    "where datetime >= '" + d1 + "' and datetime < '" + \
                    d2 + "' and ServerID in " + strServerIDs + ";"
            else:
                cmd = "select * from scan " \
                    "where datetime >= '" + d1 + "' and datetime < '" + \
                    d2 + "' and MAC in " + strServerIDs + ";"
        cur.execute(cmd)
        field_names = []
        for i in cur.description:
            field_names.append(i[0])

        time = datetime.now()
        strTime = time.strftime("%Y%m%d%H%M%S")
        strFilename = strTime + ".csv"
        fileWorkers = open(strFilename, 'w')

        fileWorkers.write("BatchID,Datetime,Model,IP,WorkerID,MAC,ServerID,Status,Progress1,Progress2,Progress3,Progress4,Progress5,Progress6,Progress7,Progress8,PoolHashRate,SelfCalHashRate,WorkingAsic,FAN1,FAN2,FAN3,FAN4,FAN5,PoolAddress,WalletAddress,Account,Password,MinerOPFreq,PowerConsumption,DHCPorFixedIP,BoardTemp1,BoardTemp2,BoardTemp3,BoardTemp4,BoardTemp5,BoardTemp6,BoardTemp7,BoardTemp8,Code,Reason\n")  # Add code and reason for "Build Version=20221102-001"
        for row in cur.fetchall():
            strData = ""
            strData += str(row[1]) + ","
            strData += row[2].strftime("%Y-%m-%d %H:%M") + ","
            strData += row[3] + ","
            strData += row[4] + ","
            strData += row[5] + ","
            strData += row[6] + ","
            strData += row[7] + ","
            strData += row[8] + ","
            strData += row[9] + ","
            strData += row[10] + ","
            strData += row[11] + ","
            strData += row[12] + ","
            strData += row[13] + ","
            strData += row[14] + ","
            strData += row[15] + ","
            strData += row[16] + ","
            strData += row[17] + ","
            strData += row[18] + ","
            strData += row[19] + ","
            strData += row[20] + ","
            strData += row[21] + ","
            strData += row[22] + ","
            strData += row[23] + ","
            strData += row[24] + ","
            strData += row[25] + ","
            strData += row[26] + ","
            strData += row[27] + ","
            strData += row[28] + ","
            strData += row[29] + ","
            strData += row[30] + ","
            strData += row[31] + ","
            strData += row[32] + ","
            strData += row[33] + ","
            strData += row[34] + ","
            strData += row[35] + ","
            strData += row[36] + ","
            strData += row[37] + ","
            strData += row[38] + ","  # "Build Version=20221102-001"
            strData += row[39] + ","  # "Build Version=20221102-001"
            strData += row[40] + ","  # "Build Version=20221102-001"
            strData += row[41] + "\n"  # "Build Version=20221102-001"
            fileWorkers.write(strData)
        fileWorkers.close()
        logger.info("Information: export to file %s created", strFilename)
        messagebox.showinfo(
            title="Export to file", message=strFilename + " created")

    def InsertWorkerToDB(cur, w):
        w.PoolHashRate = 0 if w.PoolHashRate == None else w.PoolHashRate

        w.Model = w.Model[0:5] if len(w.Model) > 5 else w.Model
        w.IP = w.IP[0:15] if len(w.IP) > 15 else w.IP
        w.Worker = w.Worker[0:15] if len(w.Worker) > 15 else w.Worker
        w.MAC = w.MAC[0:17] if len(w.MAC) > 17 else w.MAC
        w.ServerID = w.ServerID[0:32] if len(w.ServerID) > 32 else w.ServerID
        w.Status = w.Status[0:10] if len(w.Status) > 10 else w.Status
        w.Progress[0] = w.Progress[0][0:7] if len(
            w.Progress[0]) > 7 else w.Progress[0]
        w.Progress[1] = w.Progress[1][0:7] if len(
            w.Progress[1]) > 7 else w.Progress[1]
        w.Progress[2] = w.Progress[2][0:7] if len(
            w.Progress[2]) > 7 else w.Progress[2]
        w.Progress[3] = w.Progress[3][0:7] if len(
            w.Progress[3]) > 7 else w.Progress[3]
        w.Progress[4] = w.Progress[4][0:7] if len(
            w.Progress[4]) > 7 else w.Progress[4]
        w.Progress[5] = w.Progress[5][0:7] if len(
            w.Progress[5]) > 7 else w.Progress[5]
        w.Progress[6] = w.Progress[6][0:7] if len(
            w.Progress[6]) > 7 else w.Progress[6]
        w.Progress[7] = w.Progress[7][0:7] if len(
            w.Progress[7]) > 7 else w.Progress[7]
        w.PoolHashRate = w.PoolHashRate[0:10] if len(
            str(w.PoolHashRate)) > 10 else w.PoolHashRate
        w.SelfCalHashRate = w.SelfCalHashRate[0:10] if len(
            w.SelfCalHashRate) > 10 else w.SelfCalHashRate
        w.WorkingAsic = w.WorkingAsic[0:1] if len(
            str(w.WorkingAsic)) > 1 else w.WorkingAsic
        w.FanSpeed[0] = w.FanSpeed[0][0:5] if len(
            w.FanSpeed[0]) > 5 else w.FanSpeed[0]
        w.FanSpeed[1] = w.FanSpeed[1][0:5] if len(
            w.FanSpeed[1]) > 5 else w.FanSpeed[1]
        w.FanSpeed[2] = w.FanSpeed[2][0:5] if len(
            w.FanSpeed[2]) > 5 else w.FanSpeed[2]
        w.FanSpeed[3] = w.FanSpeed[3][0:5] if len(
            w.FanSpeed[3]) > 5 else w.FanSpeed[3]
        w.FanSpeed[4] = w.FanSpeed[4][0:5] if len(
            w.FanSpeed[4]) > 5 else w.FanSpeed[4]
        w.PoolAddress = w.PoolAddress[0:50] if len(
            w.PoolAddress) > 50 else w.PoolAddress
        w.WalletAddress = w.WalletAddress[0:50] if len(
            w.WalletAddress) > 50 else w.WalletAddress
        w.Account = w.Account[0:20] if len(w.Account) > 20 else w.Account
        w.Password = w.Password[0:20] if len(w.Password) > 20 else w.Password
        w.MinerOPFreq = w.MinerOPFreq[0:4] if len(
            w.MinerOPFreq) > 4 else w.MinerOPFreq
        w.PowerConsumption = w.PowerConsumption[0:7] if len(
            w.PowerConsumption) > 7 else w.PowerConsumption
        w.DHCPorFixedIP = w.DHCPorFixedIP[0:7] if len(
            w.DHCPorFixedIP) > 7 else w.DHCPorFixedIP
        w.Temperature[0] = w.Temperature[0][0:4] if len(
            w.Temperature[0]) > 4 else w.Temperature[0]
        w.Temperature[1] = w.Temperature[1][0:4] if len(
            w.Temperature[1]) > 4 else w.Temperature[1]
        w.Temperature[2] = w.Temperature[2][0:4] if len(
            w.Temperature[2]) > 4 else w.Temperature[2]
        w.Temperature[3] = w.Temperature[3][0:4] if len(
            w.Temperature[3]) > 4 else w.Temperature[3]
        w.Temperature[4] = w.Temperature[4][0:4] if len(
            w.Temperature[4]) > 4 else w.Temperature[4]
        w.Temperature[5] = w.Temperature[5][0:4] if len(
            w.Temperature[5]) > 4 else w.Temperature[5]
        w.Temperature[6] = w.Temperature[6][0:4] if len(
            w.Temperature[6]) > 4 else w.Temperature[6]
        w.Temperature[7] = w.Temperature[7][0:4] if len(
            w.Temperature[7]) > 4 else w.Temperature[7]
        w.FailDesc = w.FailDesc[0:50] if len(
            w.FailDesc) > 50 else w.FailDesc

        cmd = "INSERT INTO scan " \
            "(batch_id, datetime, Model, IP, Worker, MAC, ServerID, Status, Progress1, Progress2, Progress3, Progress4, " \
            "Progress5, Progress6, Progress7, Progress8, PoolHashRate, SelfCalHashRate, WorkingAsic, " \
            "FAN1, FAN2, FAN3, FAN4, FAN5, PoolAddress, WalletAddress, Account, Password, MinerOPFreq, " \
            "PowerConsumption, DHCPorFixedIP, BoardTemp1, BoardTemp2, BoardTemp3, BoardTemp4, " \
            "BoardTemp5, BoardTemp6, BoardTemp7, BoardTemp8, FailCode, FailDesc) " \
            "VALUES(" + str(w.batch_id) + ", '" + w.datetime.strftime("%Y-%m-%d %H:%M:%S") + \
            "', '" + w.Model + \
            "', '" + w.IP + \
            "', '" + w.Worker + \
            "', '" + w.MAC + \
            "', '" + w.ServerID + \
            "', '" + w.Status + \
            "', '" + w.Progress[0] + \
            "', '" + w.Progress[1] + \
            "', '" + w.Progress[2] + \
            "', '" + w.Progress[3] + \
            "', '" + w.Progress[4] + \
            "', '" + w.Progress[5] + \
            "', '" + w.Progress[6] + \
            "', '" + w.Progress[7] + \
            "', '" + str(w.PoolHashRate) + \
            "', '" + w.SelfCalHashRate + \
            "', '" + str(w.WorkingAsic) + \
            "', '" + w.FanSpeed[0] + \
            "', '" + w.FanSpeed[1] + \
            "', '" + w.FanSpeed[2] + \
            "', '" + w.FanSpeed[3] + \
            "', '" + w.FanSpeed[4] + \
            "', '" + w.PoolAddress + \
            "', '" + w.WalletAddress + \
            "', '" + w.Account + \
            "', '" + w.Password + \
            "', '" + w.MinerOPFreq + \
            "', '" + w.PowerConsumption + \
            "', '" + w.DHCPorFixedIP + \
            "', '" + w.Temperature[0] + \
            "', '" + w.Temperature[1] + \
            "', '" + w.Temperature[2] + \
            "', '" + w.Temperature[3] + \
            "', '" + w.Temperature[4] + \
            "', '" + w.Temperature[5] + \
            "', '" + w.Temperature[6] + \
            "', '" + w.Temperature[7] + \
            "', '" + str(w.FailCode) + \
            "', '" + w.FailDesc + "')"
        if myConfig.Verbose >= 2:
            logger.info(cmd)
        cur.execute(cmd)

    def GetCursorDB(conn):
        return conn.cursor()

    def CommitDB(conn):
        conn.commit()

    def RollbackDB(conn):
        conn.rollback()

    def CloseDB(conn, cur):
        if conn:
            cur.close()
            conn.close()

    if nPlatform == 1:
        logger.info("OS: Windows (%s)", platform.platform())
    else:
        logger.info("OS: MacOS or Linux (%s)", platform.platform())
    logger.info(
        "The PowerRayETC GUI is running. Please change to the GUI to operate it.")


class Countdown:
    def __init__(self):
        # Idel # of seconds before start to scan
        self.counter = int(myConfig.Refresh)*60
        self.thread = None  # create a new thread for the onScan when countdown == 0
        self.start = False  # True: start to countdown, False: stop to countdown
        self.scan = False

    def countdown(self):
        logger.info("Start the countdown from %d\" to 0\" then start to scan", int(
            myConfig.Refresh)*60)
        if len(listbox.curselection()) == 0:
            logger.info(
                "No item selected. Select all to be scan after %d\"", int(myConfig.Refresh)*60)
            varSelectAll.set(1)
            checkSelectAll()
        # After click the "Auto Scan" button, the self.start become True. The following while loop keep going if the self.start == True. And stop until self.start become False. (Run stop_thread)
        while self.start:
            # Change the btnScan as a countdown scan to display the counter with highlight color
            btnScan.config(text=str(self.counter))
            btnScan.config(fg='red', bg='yellow')
            self.counter -= 1
            # sleep for countdown from max value to 0 and then trigger the onScan
            sleep(1)
            # When countdown to 0 will trigger the onScan function
            if self.counter == 0:
                btnScan.config(text="Scan")
                self.counter = int(myConfig.Refresh)*60
                onScan()
                self.scan = False
                btnScan.config(text="Scan")
                btnScan.config(fg='black')
                btnScan.config(bg='#f0f0f0')
                # break

    def stop_thread(self):
        logger.info("======== Press Stop button")
        # when click the "stop" button. set self.start = False.
        self.start = False
        # Change the button text from "Stop" back to "Auto Scan"
        btnAuto.config(text="Auto Scan")
        # Re-layout the button
        if nPlatform == 1:
            btnAuto.config(pady=3)
        else:
            btnAuto.config(pady=2)
        self.scan = False
        # Change the btnScan text back to "Scan" and it's fg, bg back to normal
        btnScan.config(text="Scan")
        btnScan.config(fg='black')
        btnScan.config(bg='#f0f0f0')
        # Reset the countdown counter back to the default value
        self.counter = int(myConfig.Refresh)*60

    def start_thread(self):
        if self.start:  # True: start to countdown, False: stop to countdown. Default=False. When you click the "Auto Scan" button and the self.start is False. The following commands will not run.
            self.stop_thread()  # if self.start = True mean start to countdown. The "Auto Scan" button will become "Stop" button. So, click the "Stop" button will stop the thread
            return
        # Change the "Auto Scan" button text to "Stop"
        btnAuto.config(text="Stop")
        # Re-layout the button when you change the text from "Auto Scan" to "Stop"
        btnAuto.config(pady=10)
        # create a thread for countdown.
        logger.info("======== Press Auto Scan button")
        self.thread = threading.Thread(target=self.countdown, daemon=True)
        self.thread.start()  # Start to countdown thread.
        self.start = True  # True: start to countdown when click "Auto Scan" button


action = Countdown()

# Create a "Auto Scan" button. Click the "Auto Scan" button will run action.start_thread
if nPlatform == 1:
    btnAuto = tk.Button(frame1, width=5, pady=3, wraplength=40, text="Auto Scan",
                        command=action.start_thread)
    btnAuto.grid(row=1, column=2)
else:
    btnAuto = tk.Button(frame1, width=2, pady=2, wraplength=40, text="Auto Scan",
                        command=action.start_thread)
    btnAuto.grid(row=1, column=2)


def onClosing():
    logger.info("=== End to of PowerRayETC ===")
    root.destroy()


root.protocol("WM_DELETE_WINDOW", onClosing)

root.mainloop()
