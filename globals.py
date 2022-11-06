import json
import os
import logging.config
from datetime import datetime

def initialize():
    global logger
    logger = None
    logging.basicConfig(level=logging.WARNING)
    global POWERRAY_ETC_VERSION
    POWERRAY_ETC_VERSION = 2.00
    global POWERRAY_ETC_BUILD_VERSION
    POWERRAY_ETC_BUILD_VERSION = "Build Version=20221031-001"
    global mainGui
    mainGui = None
    global myConfig
    myConfig = Configuration()
    readConfig(myConfig)
    global bLoop
    bLoop = True
    global action
    action = None
    global varOptPr8XFan
    varOptPr8XFan = None
    global nPlatform  # 1. Win 2. Mac 3. Other (such as Linux..etc)
    nPlatform = None
    global PATH_CONFIG  # path of config.json
    PATH_CONFIG = None
    global PATH_WEBDRIVER  # path of webdriver
    PATH_WEBDRIVER = None
    global workerArray
    workerArray = []
    global dictIPtoIndex
    dictIPtoIndex = {}  # mapping IP to index number as integer
    global strLogFormater1, strLogFormater2, FHLog
    strLogFormater1 = None
    strLogFormater2 = None
    FHLog = None
    global bLevelname
    bLevelname = False


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


def readConfig(myConfig):
    PATH_CONFIG = r"./config.json"
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

