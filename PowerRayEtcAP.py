import ctypes

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
from PowerRayEtcUI import *
import globals

i = 0

# Function to call ssh to IP with root and no password
sshClient = paramiko.SSHClient()
sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sshClient.set_log_channel("paramiko")
sshPort = 22
sshUsername = 'root'
sshPassword = None
strScriptsPath = "/root/scripts/ch/"

def sshToIP(strIP):
    strReturn = ""
    globals.logger.info("ssh to IP=%s", strIP)
    NoAuthenticationMethodsAvailable = False
    try:
        sshClient.connect(strIP, sshPort,
                            sshUsername, sshPassword, timeout=float( globals.mainGui.varScanTimeout.get()), look_for_keys=False)
    except paramiko.SSHException as e:
        if str(e).find("No authentication") == 0:
            if globals.myConfig.Verbose > 0:
                globals.logger.info(e)
            NoAuthenticationMethodsAvailable = True
        else:
            strReturn = "paramiko.SSHException: unknown"
            globals.logger.error(strReturn)
            return None, strReturn
    except socket.timeout:
        strReturn = "ssh to " + strIP + " timeout"
        globals.logger.error(strReturn)
        return None, strReturn
    except Exception as e:
        if globals.myConfig.Verbose > 0:
            globals.logger.error('paramiko.Exception = ', e)
        strReturn = "paramiko.Exception: unknown"
        globals.logger.error(strReturn)
        return None, strReturn

    if NoAuthenticationMethodsAvailable:
        try:
            if not sshPassword:
                sshClient.get_transport().auth_none(sshUsername)
                return sshClient, ""
            else:
                if globals.myConfig.Verbose > 0:
                    globals.logger.error(
                        'paramiko.SSHException (No authentication) = ', e)
                strReturn = "unknown (No authentication)"
                globals.logger.error(strReturn)
                return None, strReturn
        except Exception as e:
            globals.logger.error(e)
            strReturn = "unknown (get_transport.auth_none)"
            globals.logger.error(strReturn)
            return None, strReturn

    return sshClient, strReturn

def onChanePR8XFAN():
    if globals.action.scan:  # if globals.action.scan == True. The onScan will not running. Default globals.action.scan is False.
        messagebox.showwarning(title="Another scan is running", message="Another scan is running")
        return
    globals.action.scan = True
    i = 0
    #onShow5()
    onScanT0 = datetime.now()
    filename = filedialog.askopenfilename(initialdir="./",
                                            title="Select a single column IPv4 text file",
                                            filetypes=(("Text files",
                                                        "*.txt"),
                                                        ("all files",
                                                        "*.*")))
    if filename == '':
        messagebox.showwarning(title="Warning", message="You do not select any file")
        globals.action.scan = False
        return

    handleFile = open(filename, "r")
    globals.mainGui.tvWorker.delete(*globals.mainGui.tvWorker.get_children())

    myIP = None
    myIPs = []
    for line in handleFile:
        myIP = line.strip()
        myIPs.append(myIP)
        FailCode = ""
        FailDesc = ""
        if globals.myConfig.Verbose:
            globals.logger.debug("%02d: Load IP=%s from file %s",
                            i, myIP, filename)

        client, strReturn = sshToIP(myIP)
        #client = None
        #strReturn = "Test"

        if client == None:
            if strReturn.find("unknown") >= 0:
                FailCode = 99
                FailDesc = strReturn
            else:
                FailCode = 5
                FailDesc = strReturn
            globals.mainGui.tvWorker.insert("", tk.END, text=str(i+1),
                            values=("", myIP, "Fan% set to "+globals.mainGui.varOptPr8XFan.get()+"%", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                    "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", FailCode, FailDesc), tag="yellow")
            i += 1
            continue
        
        try:
            stdin, stdout, stderr = client.exec_command(
                "rm -rf " + strScriptsPath + "; mkdir -p " + strScriptsPath)
            globals.logger.info(
                "Delete %s and re-created on the worker.", strScriptsPath)
            stderr.close()
            stdout.close()
        except Exception as e:
            globals.logger.error(e)
            FailCode = 6
            FailDesc = myIP + " exec command fail"
            stderr.close()
            stdout.close()
            client.close()
            PowerRayEtcUI.tvWorker.insert("", tk.END, text=str(i+1),
                            values=("", myIP, "Fan% set to "+varOptPr8XFan.get()+"%", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                    "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", FailCode, FailDesc), tag="red")
            i += 1
            continue
        a = "/"
        filename = "~" + globals.myConfig.OSUsername + a + "PowerRayETC/PowerRayETC/scripts/ch/?etFanSpeed.sh"
        cmd1 = "scp -p -C -r -4 " + str(filename) + " root@" + \
            myIP + ":/root/scripts/ch"
        globals.logger.info(cmd1)
        #os.system(cmd1)
        ret = subprocess.run(cmd1, shell=True, capture_output=True)
        if ret.returncode == 0:
            globals.logger.info(
                "ret = %d (OK=0 NG>0)", ret.returncode)
        else:
            globals.logger.warning(
                "ret = %d (OK=0 NG>0)", ret.returncode)
        lines = ret.stdout.decode("utf-8")
        errlines = ret.stderr.decode("utf-8")
        globals.logger.info("len(lines)=%d, len(errlines)=%d", len(lines), len(errlines))
        if len(lines) > 0:
            globals.logger.info(lines[:-2])
        if len(errlines) > 0:
            globals.logger.warning(errlines[:-2])

        filename = "~" + globals.myConfig.OSUsername + a + "PowerRayETC/PowerRayETC/scripts/ch/*.py"
        cmd2 = "scp -p -C -r -4 " + str(filename) + " root@" + \
            myIP + ":/root/scripts/ch"
        globals.logger.info(cmd2)
        ret = subprocess.run(cmd2, shell=True, stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        if ret.returncode == 0:
            globals.logger.info(
                "ret = %d (OK=0 NG>0)", ret.returncode)
        else:
            globals.logger.warning(
                "ret = %d (OK=0 NG>0)", ret.returncode)
        lines = ret.stdout.decode("utf-8")
        errlines = ret.stderr.decode("utf-8")
        globals.logger.info("len(lines)=%d, len(errlines)=%d", len(lines), len(errlines))
        if len(lines) > 0:
            globals.logger.info(lines[:-2])
        if len(errlines) > 0:
            globals.logger.warning(errlines[:-2])

        cmd3 = "chmod +x " + strScriptsPath + "*.sh ; sleep 1"
        globals.logger.info(cmd3)
        stdin, stdout, stderr = client.exec_command(cmd3)
        lines = stdout.readlines()
        errlines = stderr.readlines()
        stderr.close()
        stdout.close()
        globals.logger.info("len(lines)=%d, len(errlines)=%d", len(lines), len(errlines))
        for line in lines:
            globals.logger.info(line[:-2])
        for line in errlines:
            globals.logger.error(line[:-2])

        cmd4 = strScriptsPath + "setFanSpeed.sh " + globals.mainGui.varOptPr8XFan.get()
        globals.logger.info(cmd4)
        stdin, stdout, stderr = client.exec_command(cmd4)
        errlines = stderr.readlines()
        stderr.close()
        stdout.close()
        globals.logger.info("len(lines)=%d, len(errlines)=%d", len(lines), len(errlines))
        for line in lines:
            globals.logger.info(line[:-1])
        for line in errlines:
            globals.logger.error(line[:-1])
        client.close()

        globals.mainGui.tvWorker.insert("", tk.END, text=str(i+1),
                        values=("", myIP, "Fan duty set to "+globals.mainGui.varOptPr8XFan.get()+"%", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""), tag="white")
        i += 1

    handleFile.close()
    onScanT1 = datetime.now()
    diff = onScanT1 - onScanT0
    globals.logger.info("It takes %d seconds to load the %d records of IPv4 to set fan speed",
                int(diff.total_seconds()), i)
    globals.action.scan = False

def ff(s, pool):
    strReturn = ""
    globals.logger.info("ssh to IP=%s", strIP)
    NoAuthenticationMethodsAvailable = False
    try:
        sshClient.connect(strIP, sshPort,
                            sshUsername, sshPassword, timeout=float( globals.mainGui.varScanTimeout.get()), look_for_keys=False)
    except paramiko.SSHException as e:
        if str(e).find("No authentication") == 0:
            if globals.myConfig.Verbose > 0:
                globals.logger.info(e)
            NoAuthenticationMethodsAvailable = True
        else:
            strReturn = "paramiko.SSHException: unknown"
            globals.logger.error(strReturn)
            return None, strReturn
    except socket.timeout:
        strReturn = "ssh to " + strIP + " timeout"
        globals.logger.error(strReturn)
        return None, strReturn
    except Exception as e:
        if globals.myConfig.Verbose > 0:
            globals.logger.error('paramiko.Exception = ', e)
        strReturn = "paramiko.Exception: unknown"
        globals.logger.error(strReturn)
        return None, strReturn

    if NoAuthenticationMethodsAvailable:
        try:
            if not sshPassword:
                sshClient.get_transport().auth_none(sshUsername)
                return sshClient, ""
            else:
                if globals.myConfig.Verbose > 0:
                    globals.logger.error(
                        'paramiko.SSHException (No authentication) = ', e)
                strReturn = "unknown (No authentication)"
                globals.logger.error(strReturn)
                return None, strReturn
        except Exception as e:
            globals.logger.error(e)
            strReturn = "unknown (get_transport.auth_none)"
            globals.logger.error(strReturn)
            return None, strReturn

    return sshClient, strReturn

def onChanePR8XFAN():
    if globals.action.scan:  # if globals.action.scan == True. The onScan will not running. Default globals.action.scan is False.
        messagebox.showwarning(title="Another scan is running", message="Another scan is running")
        return
    globals.action.scan = True
    i = 0
    #onShow5()  
    onScanT0 = datetime.now()
    filename = filedialog.askopenfilename(initialdir="./",
                                            title="Select a single column IPv4 text file",
                                            filetypes=(("Text files",
                                                        "*.txt"),
                                                        ("all files",
                                                        "*.*")))
    if filename == '':
        messagebox.showwarning(title="Warning", message="You do not select any file")
        globals.action.scan = False
        return

    handleFile = open(filename, "r")
    globals.mainGui.tvWorker.delete(*globals.mainGui.tvWorker.get_children())

    myIP = None
    myIPs = []
    for line in handleFile:
        myIP = line.strip()
        myIPs.append(myIP)
        FailCode = ""
        FailDesc = ""
        if globals.myConfig.Verbose:
            globals.logger.debug("%02d: Load IP=%s from file %s",
                            i, myIP, filename)

        client, strReturn = sshToIP(myIP)
        #client = None
        #strReturn = "Test"

        if client == None:
            if strReturn.find("unknown") >= 0:
                FailCode = 99
                FailDesc = strReturn
            else:
                FailCode = 5
                FailDesc = strReturn
            globals.mainGui.tvWorker.insert("", tk.END, text=str(i+1),
                            values=("", myIP, "Fan% set to "+globals.mainGui.varOptPr8XFan.get()+"%", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                    "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", FailCode, FailDesc), tag="yellow")
            i += 1
            continue
        
        try:
            stdin, stdout, stderr = client.exec_command(
                "rm -rf " + strScriptsPath + "; mkdir -p " + strScriptsPath)
            globals.logger.info(
                "Delete %s and re-created on the worker.", strScriptsPath)
            stderr.close()
            stdout.close()
        except Exception as e:
            globals.logger.error(e)
            FailCode = 6
            FailDesc = myIP + " exec command fail"
            stderr.close()
            stdout.close()
            client.close()
            PowerRayEtcUI.tvWorker.insert("", tk.END, text=str(i+1),
                            values=("", myIP, "Fan% set to "+varOptPr8XFan.get()+"%", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                    "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", FailCode, FailDesc), tag="red")
            i += 1
            continue
        a = "/"
        filename = "~" + globals.myConfig.OSUsername + a + "PowerRayETC/PowerRayETC/scripts/ch/?etFanSpeed.sh"
        cmd1 = "scp -p -C -r -4 " + str(filename) + " root@" + \
            myIP + ":/root/scripts/ch"
        globals.logger.info(cmd1)
        #os.system(cmd1)
        ret = subprocess.run(cmd1, shell=True, capture_output=True)
        if ret.returncode == 0:
            globals.logger.info(
                "ret = %d (OK=0 NG>0)", ret.returncode)
        else:
            globals.logger.warning(
                "ret = %d (OK=0 NG>0)", ret.returncode)
        lines = ret.stdout.decode("utf-8")
        errlines = ret.stderr.decode("utf-8")
        globals.logger.info("len(lines)=%d, len(errlines)=%d", len(lines), len(errlines))
        if len(lines) > 0:
            globals.logger.info(lines[:-2])
        if len(errlines) > 0:
            globals.logger.warning(errlines[:-2])

        filename = "~" + globals.myConfig.OSUsername + a + "PowerRayETC/PowerRayETC/scripts/ch/*.py"
        cmd2 = "scp -p -C -r -4 " + str(filename) + " root@" + \
            myIP + ":/root/scripts/ch"
        globals.logger.info(cmd2)
        ret = subprocess.run(cmd2, shell=True, stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        if ret.returncode == 0:
            globals.logger.info(
                "ret = %d (OK=0 NG>0)", ret.returncode)
        else:
            globals.logger.warning(
                "ret = %d (OK=0 NG>0)", ret.returncode)
        lines = ret.stdout.decode("utf-8")
        errlines = ret.stderr.decode("utf-8")
        globals.logger.info("len(lines)=%d, len(errlines)=%d", len(lines), len(errlines))
        if len(lines) > 0:
            globals.logger.info(lines[:-2])
        if len(errlines) > 0:
            globals.logger.warning(errlines[:-2])

        cmd3 = "chmod +x " + strScriptsPath + "*.sh ; sleep 1"
        globals.logger.info(cmd3)
        stdin, stdout, stderr = client.exec_command(cmd3)
        lines = stdout.readlines()
        errlines = stderr.readlines()
        stderr.close()
        stdout.close()
        globals.logger.info("len(lines)=%d, len(errlines)=%d", len(lines), len(errlines))
        for line in lines:
            globals.logger.info(line[:-2])
        for line in errlines:
            globals.logger.error(line[:-2])

        cmd4 = strScriptsPath + "setFanSpeed.sh " + globals.mainGui.varOptPr8XFan.get()
        globals.logger.info(cmd4)
        stdin, stdout, stderr = client.exec_command(cmd4)
        errlines = stderr.readlines()
        stderr.close()
        stdout.close()
        globals.logger.info("len(lines)=%d, len(errlines)=%d", len(lines), len(errlines))
        for line in lines:
            globals.logger.info(line[:-1])
        for line in errlines:
            globals.logger.error(line[:-1])
        client.close()

        globals.mainGui.tvWorker.insert("", tk.END, text=str(i+1),
                        values=("", myIP, "Fan duty set to "+globals.mainGui.varOptPr8XFan.get()+"%", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                                "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""), tag="white")
        i += 1

    handleFile.close()
    onScanT1 = datetime.now()
    diff = onScanT1 - onScanT0
    globals.logger.info("It takes %d seconds to load the %d records of IPv4 to set fan speed",
                int(diff.total_seconds()), i)
    globals.action.scan = False

class ThreadPool(object):
    def __init__(self):
        super(ThreadPool, self).__init__()
        self.active = []
        self.lock = threading.Lock()
    def makeActive(self, name):
        with self.lock:
            self.active.append(name)
            globals.logger.debug('Running: %s', self.active)
    def makeInactive(self, name):
        with self.lock:
            self.active.remove(name)
            globals.logger.debug('Running: %s', self.active)

def f(s, pool):
    globals.logger.debug('Waiting to join the pool')
    with s:
        name = threading.current_thread().name
        pool.makeActive(name)
        time.sleep(0.5)
        pool.makeInactive(name)

def func(gui):
    # just some code around here
    globals.logger.info(str(globals.POWERRAY_ETC_VERSION))
    ident = threading.get_ident()
    #while True and globals.bLoop:
    #    globals.logger.info(f'Thread-{ident} says hi!')
    #    time.sleep(1)

def funcc(gui):
    # just some code around here
    globals.logger.info(str(globals.POWERRAY_ETC_VERSION))
    ident = threading.get_ident()
    #while True and globals.bLoop:
    #    globals.logger.info(f'Thread-{ident} says hi!')
    #    time.sleep(1)

if __name__ == "__main__":
    if platform.system() == 'Windows':
        globals.nPlatform = 1
        globals.nWebdriver = 1
        a = "\\"
        #globals.PATH_CONFIG = "C:\\Users\\" + os.getlogin() + a + "ch\\config.json"
        globals.PATH_WEBDRIVER = "C:\\Users\\" + os.getlogin() + a + "ch\\msedgedriver.exe"
    elif platform.system() == 'Darwin':  # For my Mac's develop PATH_CONFIG and PATH_WEBDRIVER
        globals.nPlatform = 2
        #globals.PATH_CONFIG = r"./config.json"
        globals.PATH_WEBDRIVER = r"./msedgedriver"
    elif platform.system() == 'Linux':
        globals.nPlatform = 3
        #globals.PATH_CONFIG = r"/root/ch/config.json"
        globals.PATH_WEBDRIVER = r"/root/ch/msedgedriver"

    # create log folder if not exist
    if not os.path.exists("log"):
        os.makedirs("log")
    # Load logging.conf
    logging.basicConfig(level=logging.DEBUG)
    logging.config.fileConfig('logging.conf')
    globals.logger = logging.getLogger('PowerRayETC')
    globals.logger.info('=== Start to of PowerRayEtcAP v%4.2f ===', globals.POWERRAY_ETC_VERSION)


    # start up the program
    root = tk.Tk()

    # pass the root in the __init__ function from PowerRayEtcUI
    globals.mainGui = PowerRayEtcUI(root)

    # Start the new thread
    theThread = threading.Thread(target=funcc, args=([globals.mainGui]))
    theThread.daemon = True
    theThread.start()

    pool = ThreadPool()
    s = threading.Semaphore(3)
    for i in range(3):
        t = threading.Thread(target=f, name='thread_'+str(i), args=(s, pool))
        t.start()    

    def onClosing():
        globals.logger.info('=== End of PowerRayEtcAP v%4.2f ===', globals.POWERRAY_ETC_VERSION)
        quit()

    root.protocol("WM_DELETE_WINDOW", onClosing)

    # loop command
    root.mainloop()