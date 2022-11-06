from PowerRayEtcAP import *
from globals import *
import sys
import tkinter as tk
from tkinter import LEFT, filedialog, messagebox, ttk
from datetime import datetime, timedelta

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

bLevelname = False

class Countdown:
    counter = None
    Thread = None
    start = None
    scan = None

    def __init__(self):
        globals.initialize()
        #globals.myConfig = Configuration()
        #readConfig(globals.myConfig)
        # Idel # of seconds before start to scan
        self.counter = int(globals.myConfig.Refresh)*60
        self.thread = None  # create a new thread for the onScan when countdown == 0
        self.start = False  # True: start to countdown, False: stop to countdown
        self.scan = False

    def countdown(self):
        globals.logger.info("Start the countdown from %d\" to 0\" then start to scan", int(
            globals.myConfig.Refresh)*60)
        '''
        if len(listbox.curselection()) == 0:
            globals.logger.info(
                "No item selected. Select all to be scan after %d\"", int(globals.myConfig.Refresh)*60)
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
                self.counter = int(globals.myConfig.Refresh)*60
                onScan()
                self.scan = False
                btnScan.config(text="Scan")
                btnScan.config(fg='black')
                btnScan.config(bg='#f0f0f0')
        '''

    def stop_thread(self):
        globals.logger.info("======== Press Stop button")
        # when click the "stop" button. set self.start = False.
        self.start = False
        # Change the button text from "Stop" back to "Auto Scan"
        btnAuto.config(text="Auto Scan")
        # Re-layout the button
        if globals.nPlatform == 1:
            self.btnAuto.config(pady=3)
        else:
            self.btnAuto.config(pady=2)
        self.scan = False
        # Change the btnScan text back to "Scan" and it's fg, bg back to normal
        btnScan.config(text="Scan")
        btnScan.config(fg='black')
        btnScan.config(bg='#f0f0f0')
        # Reset the countdown counter back to the default value
        self.counter = int(globals.myConfig.Refresh)*60

    def start_thread(self):
        if self.start:  # True: start to countdown, False: stop to countdown. Default=False. When you click the "Auto Scan" button and the self.start is False. The following commands will not run.
            self.stop_thread()  # if self.start = True mean start to countdown. The "Auto Scan" button will become "Stop" button. So, click the "Stop" button will stop the thread
            return
        # Change the "Auto Scan" button text to "Stop"
        btnAuto.config(text="Stop")
        # Re-layout the button when you change the text from "Auto Scan" to "Stop"
        btnAuto.config(pady=10)
        # create a thread for countdown.
        globals.logger.info("======== Press Auto Scan button")
        self.thread = threading.Thread(target=self.countdown, daemon=True)
        self.thread.start()  # Start to countdown thread.
        self.start = True  # True: start to countdown when click "Auto Scan" button

class PowerRayEtcUI:
    root = None
    nFontSize = 11
    ip1 = None
    ip2 = None


    # Make a regular expression
    # for validating an Ip-address
    regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''

    # Define a function for
    # validate an Ip addess


    def check(self, Ip):

        # pass the regular expression
        # and the string in search() method
        if (re.search(regex, Ip)):
            globals.logger.info("Valid Ip address")

        else:
            globals.logger.info("Invalid Ip address")


    def validate(self, P):
        test = re.compile(
            '(^\d{0,3}$|^\d{1,3}\.\d{0,3}$|^\d{1,3}\.\d{1,3}\.\d{0,3}$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{0,3}$)')
        if test.match(P):
            return True
        else:
            return False


    def ip_to_int(self, ip):
        """
        :type ip: str
        :rtype: int[]
        """

        x = ip.split(".")
        for i in range(len(x)):
            x[i] = int(x[i])
        return x

    globals.action = Countdown()

    def __init__(self, root):
        self.root = root
        strTitle = "{0}{1:04.2f}".format("PowerRay ETC Mining Dashboard - v", globals.POWERRAY_ETC_VERSION)
        self.root.title(strTitle)
        self.root.tk.call('wm', 'iconphoto', root._w,
                    tk.PhotoImage(file='PowerRayLogo.png'))
        self.root.geometry("1235x820")
        self.root.minsize(1235, 820)
        self.createUI()

    # Functions of frame1
    # Note here that Tkinter passes an event object to onselect() of listbox
    def onSelect(self, evt):
        w = evt.widget
        if len(w.curselection()) == 0:
            return
        if globals.myConfig.Verbose:
            globals.logger.info('The following item are selected:')
            for i in w.curselection():
                globals.logger.info(w.get(i))

    def checkSelectAll(self):
        if self.varSelectAll.get() == 1:
            for i in range(self.listbox.size()):
                self.listbox.select_set(i)
            if globals.myConfig.Verbose:
                globals.logger.info('The following item are selected:')
                for i in self.listbox.curselection():
                    globals.logger.info(self.listbox.get(i))
        else:
            for i in range(self.listbox.size()):
                self.listbox.select_clear(i)
            if globals.myConfig.Verbose:
                globals.logger.info('No item is selected:')

    def onPlus(self):
        top = tk.Toplevel(self.root)
        top.attributes('-topmost', 'true')
        if globals.nPlatform == 1:
            top.geometry("265x63")
        else:
            top.geometry("360x80")
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        top.geometry("+%d+%d" % (x+200, y+200))
        top.title("New IP Range")
        tk.Label(top, text="From IP:").grid(row=0, column=0, sticky='e', padx=5)
        tk.Label(top, text="To IP:").grid(row=1, column=0, sticky='e', padx=5)
        varip1 = tk.StringVar()
        vcmd1 = self.root.register(self.validate)
        ipaddr1 = tk.Entry(top, textvariable=varip1, width=23,
                        validate='key', validatecommand=(vcmd1, '%P'))
        ipaddr1.grid(row=0, column=1, padx=5, pady=5)
        varip2 = tk.StringVar()
        vcmd2 = self.root.register(self.validate)
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
            globals.logger.info("Append '%s' to scan list", strTmp)
            self.listbox.insert('end', strTmp)
            globals.myConfig.IPs.append({'From': ip1, 'To': ip2})
            cancel_btn()

        if globals.nPlatform == 1:
            btnAdd = tk.Button(top, text="Add", width=5, command=add_btn)
            btnCancel = tk.Button(top, text='Cancel', width=5, command=cancel_btn)
        else:
            btnAdd = tk.Button(top, text="Add", width=2, command=add_btn)
            btnCancel = tk.Button(top, text='Cancel', width=2, command=cancel_btn)
        btnAdd.grid(column=2, row=0)
        btnCancel.grid(column=2, row=1)

    def onMinus(self):
        if len(self.listbox.curselection()) > 0:
            nDelItem = []
            for i in self.listbox.curselection():
                nDelItem.append(i)
            for i in reversed(nDelItem):
                globals.logger.info("Delete item '%s'", self.listbox.get(i))
                globals.myConfig.IPs.remove(globals.myConfig.IPs[i])
                self.listbox.delete(i)        


    # Click "Scan" btnAuto to trigger onScan function

    onScanT0 = None  # Start datetime of worker scanning
    onScanT1 = None  # End datetime of worker scanning

    def onScan(self):
        if globals.action.scan:  # if action.scan == True. The onScan will not running. Default action.scan is False.
            return
        globals.action.scan = True  # Set to True to protect onScan running again.
        globals.workerArray.clear()  # array of worker. Clear it before scaning.
        # dictionary mapping IP to index in globals.workerArray. Clear it before scaning.
        globals.dictIPtoIndex.clear()
        #btnScan.config(fg='red', bg='yellow')
        # sleep(1)
        j = 0
        # Scan only for selection IP Ranges
        onScanT0 = datetime.now()
        nCount = 0
        globals.logger.info(
            "====== Scan all selected IPv4 range with port 22 open and valid worker's MAC address")
        for i in self.listbox.curselection():
            # Get the 'From' IP and 'To' IP strings of the selection IP Ranges
            strFrom = globals.myConfig.IPs[i]['From']
            strTo = globals.myConfig.IPs[i]['To']
            # Change IPv4 from String to 4 integers array
            lstFrom = self.ip_to_int(strFrom)
            lstTo = self.ip_to_int(strTo)
            # Warning when IP is not valid IPv4
            if len(lstFrom) != 4 or len(lstTo) != 4:
                messagebox.showwarning(
                    title="Warning", message="FromIP(" + strFrom + ") or ToIP(" + strTo + ") is not valid")
                globals.action.scan = False
                return
            # Warning when 'From' IP and 'To' IP not in the same class C
            if lstFrom[0] != lstTo[0] or lstFrom[1] != lstTo[1] or lstFrom[2] != lstTo[2]:
                messagebox.showwarning(
                    title="Warning", message="FromIP(" + strFrom + ") or ToIP(" + strTo + ") is not in the same class C")
                globals.action.scan = False
                return
            # Warning when 'From' IPv4 < 'To' IPv4
            if lstFrom[3] > lstTo[3]:
                messagebox.showwarning(
                    title="Warning", message="FromIP(" + strFrom + ") >= ToIP(" + strTo + ")")
                globals.action.scan = False
                return
            # Construct nmap command for Windows OS (nPlatform==1) and other OSs. Only check ssh port == 22
            # grep nmap result only for IP and ssh
            if globals.nPlatform == 2 or globals.nPlatform == 3:
                if globals.myConfig.Home:
                    strNmap = "sudo nmap -n -p 22 " + strFrom + "-" + \
                        str(lstTo[3]) + " | grep '" + \
                        str(lstFrom[0]) + "\\|ssh'"
                else:
                    strNmap = "sudo nmap -n -p 22 " + strFrom + "-" + \
                        str(lstTo[3]) + " | grep '" + \
                        str(lstFrom[0]) + "\\|ssh\\|MAC'"
            elif globals.nPlatform == 1:
                if globals.myConfig.Home:
                    strNmap = "nmap -n -sT -T4 -p 22 " + strFrom + "-" + str(lstTo[3]) + \
                        " | Select-String -pattern '" + str(lstFrom[0]) + "|ssh'"
                else:
                    strNmap = "nmap -n -sT -T4 -p 22 " + strFrom + "-" + str(lstTo[3]) + \
                        " | Select-String -pattern '" + \
                        str(lstFrom[0]) + "|ssh|MAC'"
            if strNmap.find("sudo") >= 0:
                globals.logger.info(
                    "Please check if you may need to enter the password of sudo command in the console or terminal")
            globals.logger.info("==== " + strNmap)

            # Run nmap and check how long nmap takes
            t0 = datetime.now()
            if globals.nPlatform == 2 or globals.nPlatform == 3:
                results = subprocess.Popen(
                    strNmap, stdout=subprocess.PIPE, shell=True).communicate()[0].split(b"\n")
            else:
                results = subprocess.Popen(
                    ["powershell", "-Command", strNmap], stdout=subprocess.PIPE).stdout
            t1 = datetime.now()
            diff = t1 - t0
            globals.logger.info("== Scan from " + strFrom +
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
                if len(strTmps) > 8 and strTmps[7] == "recognized" and globals.nPlatform == 1:
                    globals.logger.warning(bResult)
                    globals.logger.warning(
                        "Please check the nmap installed or the $Env:path include path of namp of Windows and quit the program.")
                    quit()
                if strTmps[0] == "Nmap" and strTmps[1] == "scan":
                    if len(strTmps[4]) > 10:  # Length of IPv4 shall great than 10 digits
                        if globals.nPlatform == 2 or globals.nPlatform == 3:
                            strIP = strTmps[4]
                        else:
                            strIP = strTmps[4][:-2]  # trim "\n\r" for Windows OS
                        globals.logger.debug(
                            "Get the IP %s from the nmap scan result", strIP)
                if strTmps[0] == "22/tcp":  # 2nd line include ssh port 22 is 'open' or 'close'
                    if strTmps[1] == "open":
                        nSsh = 1
                    else:
                        nSsh = 0
                    # only take care of the worker when it's ssh/22 is "open".
                    globals.logger.debug(
                        "The port 22/ssh of the IP %s is '%s'", strIP, strTmps[1])
                    if nSsh == 1:
                        globals.workerArray.append(worker())
                        globals.workerArray[j].Number = j
                        globals.workerArray[j].IP = strIP
                        globals.dictIPtoIndex[strIP] = j
                        globals.workerArray[j].Ssh = nSsh
                        j += 1
                    if globals.myConfig.Home:
                        globals.logger.debug(
                            "myConfig.Home=%d, Force to scan this worker no matter the MAC is found or not.", globals.myConfig.Home)
                        if j >= 1 and nSsh == 1:
                            globals.workerArray[j-1].bPowerRay = True
                            nCount += 1
                if strTmps[0] == "MAC":  # it's a MAC address
                    if globals.nPlatform == 1:
                        globals.logger.debug("Nmap scan result '%s'",
                                    bResult.decode("utf-8")[:-2])  # Windows remove "\r\n"
                    else:
                        globals.logger.debug("Nmap scan result '%s'",
                                    bResult.decode("utf-8"))

                    if strTmps[2][0:8] in {"68:5E:6B", "F4:3E:66"}:
                        globals.logger.debug(
                            "Only check the MAC(%s) OUI (The irst 6-digits of '%s') belong to (PowerRay) or '%s' (Bee Computing)", strTmps[2], "68:5E:6B", "F4:3E:66")
                        if nSsh == 1 and j >= 1:
                            globals.workerArray[j-1].bPowerRay = True
                            nCount += 1
                    else:
                        globals.logger.warning(
                            "The MAC OUI (The first 6-digits of '%s') doesn't belong to '%s' (PowerRay) or '%s' (Bee Computing). Skit it.", strTmps[2], "68:5E:6B", "F4:3E:66")
                        if j >= 1:
                            globals.workerArray[j-1].MAC = strTmps[2]
                            globals.workerArray[j-1].bPowerRay = False
                            globals.workerArray[j-1].FailCode = 2
                            globals.workerArray[j-1].FailDesc = \
                                "The MAC OUI (" + \
                                strTmps[2][0:8] + ") is not valid"
                            if globals.myConfig.Home:  # if globals.myConfig.Home != 0 to ignore MAC address OUI checking
                                globals.logger.info(
                                    "myConfig.Home = %d != 0 to ignore MAC OUI checking", globals.myConfig.Home)
                                if nSsh == 1 and j >= 1:
                                    globals.workerArray[j-1].bPowerRay = True
                                    nCount += 1
                            globals.workerArray[j-1].Ssh = 1

            globals.action.scan = False  # finish the scan for all IPs
            globals.logger.info(
                "====== Finish IP & port=22 scan and set action.scan to False and please wait for brower launch for a moment")

        # Start to gather information of each worker when it's ssh/22 is "open"
        globals.logger.info(
            "====== Star to collect valid worker's information")
        for i in range(len(globals.workerArray)):
            if nCount == 0:
                globals.logger.info("No worker found.")
                return
            if globals.action.scan: 
                return
            # ssh to worker's IP. username=root, no password
            myIP = globals.workerArray[i].IP
            if bLevelname:
                globals.logger.handlers[0].setFormatter(logging.Formatter( globals.strLogFormater2))
            if  globals.FHLog != None:
                 globals.FHLog.setFormatter(logging.Formatter( globals.strLogFormater2))
            if i == 0:
                globals.logger.warning("==== Start to scan all availiable IPs")
            globals.logger.warning("== Scan " + myIP)
            if bLevelname:
                globals.logger.handlers[0].setFormatter(logging.Formatter( globals.strLogFormater1))
            if  globals.FHLog != None:
                 globals.FHLog.setFormatter(logging.Formatter( globals.strLogFormater1))
            client, strReturn = self.sshToWoker(myIP)
            if client == None:
                globals.workerArray[i].FailDesc = "Can not ssh to " + myIP
                globals.workerArray[i].FailCode = 2
                continue

            bCreateFolder = True
            # Create /root/scripts/ch and copy all scripts from local to worker. And change the *.sh to executable
            if bCreateFolder:
                stdin, stdout, stderr = client.exec_command(
                    "rm -rf " + strScriptsPath + "; mkdir -p " + strScriptsPath)
                globals.logger.info(
                    "Delete %s and re-created on the worker.", strScriptsPath)
                stdout.close()
                # scp all scripts and python files to worker
                if globals.nPlatform == 1:  # Windows 10/11 or Server
                    # Create a PowerShell scrip file go.ps1
                    # C:
                    # cd $HOME\ch
                    # ..\AppData\Local\Programs\Python\Python310\python.exe $HOME\ch\PowerRayETC.[ver].py
                    a = "\\"
                    filename = "C:\\Users\\" + os.getlogin() + a + "ch\\scripts\\ch"
                    globals.logger.info(
                        "Copy all the scripts from folder '%s'", str(filename))
                    cmd1 = "scp -p -C -r -4 " + str(filename) + " root@" + \
                        globals.workerArray[i].IP + ":/root/scripts"
                    cmd2 = "chmod +x " + strScriptsPath + "*.sh ; sleep 1"
                    ret = subprocess.run(cmd1, shell=True, stdout=subprocess.PIPE,
                                        stdin=subprocess.PIPE, stderr=subprocess.PIPE)
                    if ret.returncode == 0:
                        globals.logger.info(
                            "Run '%s' on Windows. The return = %d (OK=0 NG>0)", cmd1, ret.returncode)
                    else:
                        globals.logger.warning(
                            "Run '%s' on Windows. The return = %d (OK=0 NG>0)", cmd1, ret.returncode)
                    lines = ret.stdout.decode("utf-8")
                    errlines = ret.stderr.decode("utf-8")
                    globals.logger.info("len of stdout=%d, stderr=%d",
                                len(lines), len(errlines))
                    if len(lines) > 0:
                        globals.logger.info(lines[0:-1])
                    if len(errlines) > 0:
                        strTmps = errlines.split("\r\n")
                        for strTmp in strTmps:
                            if len(strTmp) > 0 and strTmp[-1] == "\n":  # v1.03
                                strTmp = strTmp[0:-1]
                            if len(strTmp) > 0:
                                if len(errlines) >= 100:
                                    if strTmp.find("fingerprint") >= 0:
                                        strTemps = strTmp.split("\n")
                                        if len(strTemps) == 2:
                                            globals.logger.warning(strTemps[0] + strTemps[1])
                                        else:
                                            for strTemp in strTemps:
                                                globals.logger.warning(strTemp)
                        globals.workerArray[i].FailCode = 2
                        globals.workerArray[i].FailDesc = "Can not copy scripts to worker"
                        continue

                    if ret.returncode == 0:
                        globals.logger.info("Run '%s' on worker.", cmd2)
                        stdin, stdout, stderr = client.exec_command(cmd2)
                        lines = stdout.readlines()
                        errlines = stderr.readlines()
                        stderr.close()
                        stdout.close()
                        globals.logger.info("len of stdout=%d, stderr=%d",
                                    len(lines), len(errlines))
                        for line in errlines:
                            globals.logger.error(line[:-1])
                        for line in lines:
                            globals.logger.info(line[:-1])
                else:
                    cmd1 = "scp ./scripts/ch/*.* root@" + \
                        globals.workerArray[i].IP + ":" + \
                        strScriptsPath + ". > /dev/null 2>&1"
                    globals.logger.info(
                        "Run '%s' on local Linux like OS.", cmd1)
                    os.system(cmd1)
                    cmd2 = "chmod +x " + strScriptsPath + "*.sh"
                    globals.logger.info("Run '%s' on remote worker.", cmd2)
                    stdin, stdout, stderr = client.exec_command(cmd2)
                    lines = stdout.readlines()
                    errlines = stderr.readlines()
                    stdout.close()
                    stderr.close()
                    if len(lines) > 0:
                        for line in lines:
                            globals.logger.info(line)
                    if len(errlines) == 0:
                        globals.logger.info("Run '%s' successfully", cmd2)
                    else:
                        for line in errlines:
                            globals.logger.error(line)
                        globals.logger.error("Run '%' failed", cmd2)

            # Get worker's MAC address of br-lan and worker's name
            cmd = strScriptsPath + "getMACnWorker.sh 14400"
            stdin, stdout, stderr = client.exec_command(cmd)
            globals.logger.info("Run '%s' on worker.", cmd)
            errLines = stderr.readlines()
            if len(errLines) > 0 and errLines[0].find("Permission"):
                globals.workerArray[i].MAC = "NA"
                globals.workerArray[i].Worker = "NA"
                globals.logger.warning(
                    "getMACnWorker.sh permission denied. Set MAC and Worker as 'NA'")
            else:
                lines = stdout.readlines()
                globals.workerArray[i].MAC = lines[0][:-1]
                if lines[1][:-1] == "IOSCAN":
                    globals.workerArray[i].Worker = ""
                else:
                    globals.workerArray[i].Worker = lines[1][:-1]
                globals.logger.info("getMACnWorker.sh return MAC=%s and Worker='%s'",
                            globals.workerArray[i].MAC, globals.workerArray[i].Worker)
                if lines[1][:-1] == "IOSCAN" and lines[2][:-1] == "4hr":
                    globals.workerArray[i].FailCode = 1
                    globals.workerArray[i].FailDesc = "More than 4 hours still in IOSCAN state"
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
                globals.logger.warning(
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
                    server = globals.myConfig.mssqlHost
                    database = globals.myConfig.mssqlDatabase
                    username = globals.myConfig.mssqlUser
                    password = globals.myConfig.mssqlPassword
                    conn = pymssql.connect(server=server, user=username,
                                        password=password, database=database)
                    nMSSQL = 1
                    if conn:
                        globals.logger.info(
                            "Connect to MS-SQL production database successfully")
                        cursor = conn.cursor()
                        strModel = 'NA'
                        strServerID = 'NA'
                        if cursor:
                            strMAC = globals.workerArray[i].MAC
                            cmd = "exec " + globals.myConfig.mssqlStoreProcedure + "'"+strMAC+"';"
                            cursor.execute(cmd)
                            globals.logger.info(
                                "Run MS-SQL stored procedure '%s'", cmd)
                            row = cursor.fetchall()
                            if row and len(row[0]) == 2:
                                if row[0][0] is None:
                                    globals.logger.warning("IP=%s has no ServerID in MS-SQL",
                                                globals.workerArray[i].IP)
                                else:
                                    strServerID = row[0][0]
                                    globals.logger.info(
                                        "The ServerID=%s from MS-SQL Stored Procedure", strServerID)
                                if row[0][1] is None:
                                    globals.logger.warning("IP=%s has no strModel in MS-SQL",
                                                globals.workerArray[i].IP)
                                else:
                                    strModel = row[0][1]
                                    globals.logger.info(
                                        "The Model=%s from MS-SQL Stored Procedure", strModel)
                                globals.workerArray[i].ServerID = strServerID
                                globals.workerArray[i].Model = strModel
                                cmd = "echo " + strServerID + " > /root/ServerID; echo " + strModel + " > /root/Model"
                                stdin, stdout, stderr = client.exec_command(cmd)
                                globals.logger.info(
                                    "echo ServerID & Model in worker's /root directory")
                except Exception as e:
                    print(e)
                    pass

            # Get Model from /root/Model
            cmd = strScriptsPath + "getModel.sh"
            stdin, stdout, stderr = client.exec_command(cmd)
            lines = stdout.readlines()
            if len(lines) > 0 and lines[0].find("No such file or directory") != -1:
                globals.logger.warning(
                    "Run '%s' and can't find /root/Model. Set /root/Model as 'NA'")
                globals.workerArray[i].Model = 'NA'
            elif len(lines) > 0:
                strModel = lines[0][:-1]
                globals.logger.info("Model=%s", strModel)
                globals.workerArray[i].Model = strModel
            else:
                globals.logger.warning(
                    "Unknown reason can't get /root/Model. echo 'NA' > /root/Model")
                globals.workerArray[i].Model = 'NA'
            stdout.close()

            # Get ServerID from /root/ServerID
            strServerID = ''
            strModel = ''
            stdin, stdout, stderr = client.exec_command(
                strScriptsPath + "getServerID.sh")
            lines = stdout.readlines()
            if len(lines) > 0 and lines[0].find("No such file or directory") != -1:
                globals.logger.warning(
                    "Can't find /root/ServerID. echo 'NA' > /root/ServerID")
                globals.workerArray[i].ServerID = 'NA'
            elif len(lines) > 0:
                strServerID = lines[0][:-1]
                globals.workerArray[i].ServerID = strServerID
            else:
                globals.workerArray[i].ServerID = 'NA'
            stdout.close()

            globals.logger.info("IP=%s, Worker=%s, MAC=%s, Model=%s, ServerID=%s",
                        globals.workerArray[i].IP, globals.workerArray[i].Worker, globals.workerArray[i].MAC, strModel, strServerID)

            def getRemoteScript(client, scriptfile):
                strReturn = ''
                cmd = strScriptsPath + scriptfile
                globals.logger.info("run remote command=%s", cmd)
                stdin, stdout, stderr = client.exec_command(cmd)
                lines = stdout.readlines()
                errlines = stderr.readlines()
                globals.logger.info("len of stdout=%d, stderr=%d",
                            len(lines), len(errlines))
                bPMBus = False
                for line in errlines:
                    if line.find("PMBus.py") > 0:
                        bPMBus = True
                        break
                if bPMBus:
                    globals.logger.info(
                        "python3 /root/scripts/ch/PMBus.py and could be I2C_SMBUS issue")
                for line in errlines:
                    if line.find("OSError: [Errno 71]") == 0:
                        globals.logger.info(line[:-1])
                    else:
                        globals.logger.error(line[:-1])
                for line in lines:
                    if line[0] == "'":
                        globals.logger.info(scriptfile + " -> " + line[1:-2])
                    else:
                        globals.logger.info(scriptfile + " -> " + line[:-1])
                if len(lines) >= 1:
                    if lines[0][0] == "'":
                        strReturn = lines[0][1:-2]
                    else:
                        strReturn = lines[0][0:-1]
                globals.logger.info("strReturn=%s", strReturn)
                stderr.close()
                stdout.close()
                if strReturn == '':
                    strReturn = 'NA'
                globals.logger.info("return %s", strReturn)
                return strReturn

            # Get pool address from /etc/config/cgminer
            strTmp = getRemoteScript(client, "getPoolAddress.sh")
            globals.workerArray[i].PoolAddress = strTmp

            # Get Wallet address from /etc/config/cgminer
            strTmp = getRemoteScript(client, "getWalletAddress.sh")
            globals.workerArray[i].WalletAddress = strTmp

            globals.workerArray[i].Account = 'NA'

            # Get password from /etc/config/cgminer
            strTmp = getRemoteScript(client, "getPassword.sh")
            globals.workerArray[i].Password = strTmp

            # Get Miner OP Freq from /etc/config/cgminer
            strTmp = getRemoteScript(client, "getMinerOPFreq.sh")
            globals.workerArray[i].MinerOPFreq = strTmp

            # Get hostname from /etc/config/system
            strTmp = getRemoteScript(client, "getHostname.sh")
            globals.workerArray[i].Hostname = strTmp

            # Get miner's status from different combination of situations
            cmd = strScriptsPath + "getStatus.sh 300"
            if globals.workerArray[i].FailCode == 0:
                globals.workerArray[i].FailDesc = ''
            globals.logger.info("run remote command=%s", cmd)
            stdin, stdout, stderr = client.exec_command(cmd)
            lines = stdout.readlines()
            errlines = stderr.readlines()
            stderr.close()
            stdout.close()
            globals.logger.info("len of stdout=%d, stderr=%d",
                        len(lines), len(errlines))
            for line in errlines:
                globals.logger.error(line[:-1])
            strStatus = "Unknown"
            if len(lines) >= 1:
                strStatus = lines[0][:-1]
                if strStatus[0:8] == "FailCode":
                    globals.logger.error(strStatus)
                    strTmps = strStatus.split(',')
                    strStatus = "Fail"
                    globals.workerArray[i].Status = strStatus
                    globals.workerArray[i].FailCode = strTmps[1]
                    globals.workerArray[i].FailDesc = strTmps[2]
                    if len(lines) >= 2:
                        strStatus = lines[1][:-1]
                        if strStatus == "IOSCAN":
                            globals.logger.info("strStatus=%s", strStatus)
                elif strStatus[0:6] == "IOSCAN":
                    strStatus = "IOSCAN"
            globals.workerArray[i].Status = strStatus

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
                                globals.workerArray[i].Progress.append(strPercent)
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
                            globals.workerArray[i].Progress.append(strPercent)
            for j in range(8-len(globals.workerArray[i].Progress)):
                globals.workerArray[i].Progress.append('NA')
            stdout.close()

            # Get board temperatures from "python3 /root/ft930_control/FT930_control.py". PR_8X, PR_1U and PR_SB has different number of board temperatures
            cmd = strScriptsPath + "getBoardTemp.sh"
            stdin, stdout, stderr = client.exec_command(cmd)
            lines = stdout.readlines()
            errlines = stderr.readlines()
            for line in errlines:
                globals.logger.info(line[:-1])
            for line in lines:
                line = line[:-1]
                globals.workerArray[i].Temperature.append(line)
            for j in range(8-len(globals.workerArray[i].Temperature)):
                globals.workerArray[i].Temperature.append('NA')
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
                    globals.logger.warning(
                        "No module named 'smbus2' on IP=%s", globals.workerArray[i].IP)
            stderr.close()

            if bSmbus2:
                # cmd = "pip3 install --trusted-host pypi.org smbus2"
                cmd = "python3 -m pip install --trusted-host files.pythonhosted.org --trusted-host pypi.org --trusted-host pypi.python.org smbus2"
                globals.logger.info("Install smbus2 via '%s'", cmd)
                stdin, stdout, stderr = client.exec_command(cmd)
                lines = stdout.readlines()
                for line in lines:
                    globals.logger.info(line[:-1])
                errlines = stderr.readlines()
                for line in errlines:
                    globals.logger.warning(line[:-1])
                stdout.close()
                stderr.close()

            # Get FAN speed from ~/scripts/ch/getFanSpeed.sh
            nFanSpeed = 0
            cmd = strScriptsPath + "getFanSpeed.sh 2>/dev/null"
            globals.logger.info("Before run '%s'", cmd)
            try:
                stdin, stdout, stderr = client.exec_command(cmd)
                globals.logger.info("After run '%s'", cmd)
                errlines = stderr.readlines()
                lines = stdout.readlines()
                stderr.close()
                stdout.close()
                globals.logger.info("len of stdout=%d, stderr=%d",
                            len(lines), len(errlines))
                for line in errlines:
                    globals.logger.error(line[:-1])
                for line in lines:
                    globals.logger.info("'" + line[:-1] + "'")
                    strTmp = line[:-1]
                    if strTmp == 'Initializing PMBUS... ':
                        globals.workerArray[i].FanSpeed.append('NA')
                        nFanSpeed += 1
                        break
                    else:
                        nPos = strTmp.find('.')
                        line = line[0:nPos]
                        globals.workerArray[i].FanSpeed.append(line)
                    nFanSpeed += 1
            except Exception as e:
                globals.logger.error(e)
            if nFanSpeed < 5:
                for j in range(nFanSpeed, 5):
                    globals.workerArray[i].FanSpeed.append("NA")
                    globals.logger.info("append('NA') for %d", j)

            # Get power from ~/scripts/ch/getPower.sh
            strTmp = getRemoteScript(client, "getPower.sh")
            if strTmp == '':
                strTmp = 'NA'
            globals.workerArray[i].PowerConsumption = strTmp

            # Get WorkingAsic from /root/log/messages or /tmp/log/messages for different control board
            if (globals.workerArray[i].Hostname == "RTD1619B"):
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
                globals.workerArray[i].HashboardAsic[nHashboard][nAsic] = 1
            for ii in range(4):
                for jj in range(2):
                    if globals.workerArray[i].HashboardAsic[ii][jj]:
                        globals.workerArray[i].WorkingAsic += 1
            time.sleep(1)
            stdout.close()
            client.close()

        if bLevelname:
            globals.logger.handlers[0].setFormatter(logging.Formatter( globals.strLogFormater2))
        if  globals.FHLog != None:
             globals.FHLog.setFormatter(logging.Formatter( globals.strLogFormater2))
        globals.logger.info("======== Start webdriver parsing")
        if bLevelname:
            globals.logger.handlers[0].setFormatter(logging.Formatter( globals.strLogFormater1))
        if  globals.FHLog != None:
             globals.FHLog.setFormatter(logging.Formatter( globals.strLogFormater1))
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
                globals.logger.handlers[0].setFormatter(logging.Formatter( globals.strLogFormater2))
            if  globals.FHLog != None:
                 globals.FHLog.setFormatter(logging.Formatter( globals.strLogFormater2))
            globals.logger.warning("==== Launch the browser to parse the worker's CurrentHashrate")
            for walletAddress in globals.myConfig.URL:
                strURL = "https://etc.ethermine.org/miners/" + walletAddress + "/dashboard"
                globals.logger.warning("== Launch '%s'", strURL)
                if bLevelname:
                    globals.logger.handlers[0].setFormatter(logging.Formatter( globals.strLogFormater1))
                if  globals.FHLog != None:
                     globals.FHLog.setFormatter(logging.Formatter( globals.strLogFormater1))
                driver.get(strURL)
                driver.implicitly_wait(60)
                driver.minimize_window()

                elements = driver.find_elements(By.CLASS_NAME, 'table-body')

                for element in elements:
                    x = element.get_attribute('innerHTML')
                    if globals.myConfig.Verbose >= 6:
                        globals.logger.info("innerHTML=%s", str(x))
                    soup = BeautifulSoup(x, "html.parser")
                    if globals.myConfig.Verbose >= 5:
                        globals.logger.info("soup=%s", str(soup))
                    rows = soup.find_all("td", class_="string")
                    if globals.myConfig.Verbose >= 4:
                        globals.logger.info("rows=%s", str(rows))
                    for row in rows:
                        if globals.myConfig.Verbose >= 3:
                            globals.logger.info("row=%s", str(row))
                        if len(row.attrs) == 4:  # Name
                            strIP = row.text.replace("-", ".")

                    rows = soup.find_all("td", class_="number")
                    if globals.myConfig.Verbose >= 4:
                        globals.logger.info("rows=%s", str(rows))
                    for row in rows:
                        if globals.myConfig.Verbose >= 3:
                            globals.logger.info("row=%s", str(row))
                        if row.attrs['data-label'] == "Current Hashrate":
                            if globals.myConfig.Verbose >= 2:
                                globals.logger.info(
                                    "row.attrs['data-label']=%s", row.attrs['data-label'])
                            fCurrentHashrate = 0.0
                            if row.text != '0':
                                if globals.myConfig.Verbose >= 2:
                                    globals.logger.info(
                                        "row.text=%s, row.attrs['unit']=%s", row.text, row.attrs['unit'])
                                if row.attrs['unit'] == "GH/s":
                                    fCurrentHashrate = float(row.text)*1000
                                    if globals.myConfig.Verbose >= 2:
                                        globals.logger.info("IP=%s, unit=%s, unit=%s -> %7.1f M/s",
                                                    strIP, row.text, row.attrs['unit'], fCurrentHashrate)
                                else:
                                    fCurrentHashrate = float(row.text)
                                    if globals.myConfig.Verbose >= 2:
                                        globals.logger.info(
                                            "IP=%s, unit = None -> current Hashrate = %7.1f M/s", strIP, fCurrentHashrate)

                    strTestIP = strIP
                    fTestCurrentHashrate = fCurrentHashrate
                    if strIP in globals.dictIPtoIndex:
                        globals.workerArray[globals.dictIPtoIndex[strIP]
                                    ].PoolHashRate = fCurrentHashrate
                        globals.workerArray[globals.dictIPtoIndex[strIP]].Web = 1
                        globals.logger.info(
                            "IP=%s current Hashrate = %10.3f M/s", strIP, fCurrentHashrate)
            driver.quit()
            globals.logger.info("Close the browser")
        except Exception as e:
            globals.logger.error('webdriver.Exception = ', e)


    # ssh functions
    def sshToWoker(self, strIP):
        strReturn = ""
        globals.logger.info("ssh to IP=%s", strIP)
        bPowerRay = globals.workerArray[globals.dictIPtoIndex[strIP]].bPowerRay
        if bPowerRay == False:
            return None, strReturn

        NoAuthenticationMethodsAvailable = False

        try:
            sshClient.connect(strIP, sshPort,
                            sshUsername, sshPassword, timeout=float(self.varScanTimeout.get()), look_for_keys=False)
        except paramiko.SSHException as e:
            if str(e).find("No authentication") == 0:
                globals.logger.info(e)
                NoAuthenticationMethodsAvailable = True
            else:
                globals.logger.error(e)
                strException = str(e)
                if strException.find("Host key for server") >= 0:
                    strReturn = "Host key for server '192.168.88.99' does not match"
                    return None, strReturn
        except socket.timeout:
            globals.logger.warning("Warning: ssh to %s timeout", strIP)
            globals.workerArray[globals.dictIPtoIndex[strIP]].bPowerRay = False
            globals.workerArray[globals.dictIPtoIndex[strIP]].FailCode = 2
            globals.workerArray[globals.dictIPtoIndex[strIP]
                        ].FailDesc = "ssh to " + strIP + " timeout"
            return None, strReturn
        except Exception as e:
            globals.logger.error('paramiko.Exception = ', e)

        if NoAuthenticationMethodsAvailable:
            try:
                if not sshPassword:
                    sshClient.get_transport().auth_none(sshUsername)
                    return sshClient, ""
                else:
                    raise e
            except Exception as e:
                globals.logger.error(e)
                return None, strReturn

        return sshClient, strReturn

    sshPort = 22
    sshUsername = 'root'
    sshPassword = None
    strScriptsPath = "/root/scripts/ch/"

    def sshToIP(self, strIP):
        strReturn = ""
        globals.logger.info("ssh to IP=%s", strIP)
        NoAuthenticationMethodsAvailable = False
        try:
            sshClient.connect(strIP, sshPort,
                              sshUsername, sshPassword, timeout=float(self.varScanTimeout.get()), look_for_keys=False)
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

    # Functions of frame2
    def ChangePoolConfiguration(self, PoolIP, changed21, changed22, changed23):
        arg1 = "\"'" + changed21 + "'\""
        arg2 = "\"'" + changed22 + "'\""
        arg3 = "\"'" + changed23 + "'\""
        client, strReturn = sshToWoker(PoolIP)
        if client == None:
            myIP = PoolIP
            globals.workerArray[globals.dictIPtoIndex[myIP]
                        ].FailDesc = "Can not ssh to " + myIP
            globals.workerArray[globals.dictIPtoIndex[myIP]].FailCode = 2
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

    def onChangeAll(self):
        if self.varChk21.get() == 0 and self.varChk22.get() == 0 and self.varChk23.get() == 0:
            messagebox.showwarning(
                title="Warning", message="No checkbox selected.")
        else:
            if not messagebox.askokcancel("Confirm to change?", message="Do you confirm to change ALL items?"):
                return
            for item in self.tvWorker.get_children():
                item_text = self.tvWorker.item(item, "values")
                PoolIP = item_text[self.tvWorker['columns'].index("IP")]
                changed21 = ""
                changed22 = ""
                changed23 = ""
                if self.varChk21.get():
                    changed21 = self.varOpt21.get()
                    self.tvWorker.set(item, self.tvWorker['columns'].index(
                        "PoolAddress"), changed21)
                if self.varChk22.get():
                    changed22 = self.varOpt22.get()
                    self.tvWorker.set(item, self.tvWorker['columns'].index(
                        "WalletAddress"), changed22)
                if self.varChk23.get():
                    changed23 = self.varOpt23.get()
                    self.tvWorker.set(item, self.tvWorker['columns'].index(
                        "Password"), changed23)
                # Change the pool configuration on the select target IP address
                ChangePoolConfiguration(
                    self, PoolIP, changed21, changed22, changed23)

    def onChangeSelected(self):
        if len(self.tvWorker.selection()) == 0:
            messagebox.showwarning(
                title="Warning", message="You do not select any row.")
        elif self.varChk21.get() == 0 and self.varChk22.get() == 0 and self.varChk23.get() == 0:
            messagebox.showwarning(
                title="Warning", message="No checkbox selected.")
        else:
            if not messagebox.askokcancel("Confirm to change?", message="Do you confirm to change the selected items?"):
                return
            for item in self.tvWorker.selection():
                item_text = self.tvWorker.item(item, "values")
                PoolIP = item_text[self.tvWorker['columns'].index("IP")]
                changed21 = ""
                changed22 = ""
                changed23 = ""
                if self.varChk21.get():
                    changed21 = self.varOpt21.get()
                    self.tvWorker.set(item, self.tvWorker['columns'].index(
                        "PoolAddress"), changed21)
                if self.varChk22.get():
                    changed22 = self.varOpt22.get()
                    self.tvWorker.set(item, self.tvWorker['columns'].index(
                        "WalletAddress"), changed22)
                if self.varChk23.get():
                    changed23 = self.varOpt23.get()
                    self.tvWorker.set(item, self.tvWorker['columns'].index(
                        "Password"), changed23)
                # Change the pool configuration on the select target IP address
                ChangePoolConfiguration(
                    self, PoolIP, changed21, changed22, changed23)


    def createUI(self):
        if globals.nPlatform == 1:
            self.frame1 = tk.LabelFrame(self.root, text="IP Range",
                                labelanchor="nw")
            self.frame1.place(x=10, y=5, height=180, width=400)
            self.varSelectAll = tk.IntVar()
            self.c1 = tk.Checkbutton(self.frame1, variable=self.varSelectAll, text='Select All',
                                onvalue=1, offvalue=0, command=checkSelectAll, width=30, anchor='w')
            self.c1.grid(column=0, row=0)

            self.btnPlus = tk.Button(self.frame1, text="+", width=5, command=self.onPlus)
            self.btnMinus = tk.Button(self.frame1, text='-', width=5, command=self.onMinus)
            self.btnScan = tk.Button(self.frame1, text="Scan", width=5,
                                pady=10, command=self.onScan)
            self.btnLoadIP = tk.Button(
                self.frame1, width=5, pady=3, wraplength=40, text="Load File")#, command=onLoadIPList)
            self.btnLoadIP.grid(row=2, column=1, padx=2)
            self.btnScanIP = tk.Button(
                self.frame1, width=5, pady=3, wraplength=40, text="Scan File")#, command=onScanList)
            self.btnScanIP.grid(row=2, column=2, padx=2)

            self.btnPlus.grid(row=0, column=1, padx=5)
            self.btnMinus.grid(row=0, column=2, padx=5)
            self.btnScan.grid(row=1, column=1, padx=5)

            self.listbox = tk.Listbox(self.frame1, height=6, width=30, fg="black",
                                activestyle='dotbox', font="Helvetica", bg="white", selectmode="extended")
        else:
            self.frame1 = tk.LabelFrame(self.root, text="IP Range",
                                labelanchor="nw")
            self.frame1.place(x=10, y=5, height=160, width=400)
            
            self.varSelectAll = tk.IntVar()
            self.c1 = tk.Checkbutton(self.frame1, variable=self.varSelectAll, text='Select All',
                                onvalue=1, offvalue=0, command=self.checkSelectAll, width=30, anchor='w')
            self.c1.grid(row=0, column=0)
            
            self.btnPlus = tk.Button(self.frame1, text="+", width=2, command=self.onPlus)
            self.btnMinus = tk.Button(self.frame1, text='-', width=2, command=self.onMinus)
            self.btnScan = tk.Button(self.frame1, text="Scan", width=2, pady=10, command=self.onScan)
            #self.btnLoadIP = tk.Button(
            #    self.frame1, width=2, pady=2, wraplength=40, text="Load File", command=onLoadIPList)
            self.btnLoadIP = tk.Button(
                self.frame1, width=2, pady=2, wraplength=40, text="Load File")
            self.btnLoadIP.grid(row=2, column=1, padx=2)
            #self.btnScanIP = tk.Button(
            #    self.frame1, width=2, pady=2, wraplength=40, text="Scan File", command=onScanList)
            self.btnScanIP = tk.Button(
                self.frame1, width=2, pady=2, wraplength=40, text="Scan File")
            self.btnScanIP.grid(row=2, column=2, padx=2)

            self.btnPlus.grid(row=0, column=1)
            self.btnMinus.grid(row=0, column=2)
            self.btnScan.grid(row=1, column=1)

            self.listbox = tk.Listbox(self.frame1, height=6, width=30, fg="white",
                                activestyle='dotbox', font="Helvetica", bg="black", selectmode="extended")
        j = 1
        for i in globals.myConfig.IPs:
            self.listbox.insert(j, i['From'] + ' ~ ' + i['To'])
            j += 1

        self.listbox.grid(row=1, column=0, rowspan=2, pady=5)
        self.listbox.bind('<<ListboxSelect>>', self.onSelect)
        #self.btnAuto = tk.Button(self.frame1, width=2, pady=2, wraplength=40, text="Auto Scan",
        #                    command=action.start_thread)
        self.btnAuto = tk.Button(self.frame1, width=2, pady=2, wraplength=40, text="Auto Scan")
        self.btnAuto.grid(row=1, column=2)


        # 2nd frame for pool configuration
        if globals.nPlatform == 1:
            self.frame2 = tk.LabelFrame(
                self.root, text="Pool Configuration", labelanchor="nw")
            self.frame2.place(x=420, y=5, height=145, width=800)
        else:
            self.frame2 = tk.LabelFrame(
                self.root, text="Pool Configuration", labelanchor="nw")
            self.frame2.place(x=420, y=5, height=125, width=800)

        self.varChk21 = tk.IntVar()
        self.chk21 = tk.Checkbutton(self.frame2, variable=self.varChk21, text='Pool',
                            onvalue=1, offvalue=0, width=10, anchor='w')
        self.chk21.grid(row=0, column=0)
        self.varChk22 = tk.IntVar()
        self.chk22 = tk.Checkbutton(self.frame2, variable=self.varChk22, text='Wallet',
                            onvalue=1, offvalue=0, width=10, anchor='w')
        self.chk22.grid(row=1, column=0)
        self.varChk23 = tk.IntVar()
        self.chk23 = tk.Checkbutton(self.frame2, variable=self.varChk23, text='Password',
                            onvalue=1, offvalue=0, width=10, anchor='w')
        self.chk23.grid(row=2, column=0)

        self.OptionList21 = globals.myConfig.Pool
        self.varOpt21 = tk.StringVar()
        self.varOpt21.set(self.OptionList21[0])
        self.opt21 = tk.OptionMenu(self.frame2, self.varOpt21, *self.OptionList21)
        if globals.nPlatform == 1:
            self.opt21.config(width=45)
        else:
            self.opt21.config(width=35)
        self.opt21.config(anchor=tk.W)
        self.opt21.grid(row=0, column=1, sticky=tk.W)

        self.OptionList22 = globals.myConfig.Wallet
        self.varOpt22 = tk.StringVar()
        self.varOpt22.set(self.OptionList22[0])
        self.opt22 = tk.OptionMenu(self.frame2, self.varOpt22, *self.OptionList22)
        if globals.nPlatform == 1:
            self.opt22.config(width=45)
        else:
            self.opt22.config(width=35)
        self.opt22.config(anchor=tk.W)
        self.opt22.grid(row=1, column=1, sticky=tk.W)

        self.OptionList23 = globals.myConfig.Password

        self.varOpt23 = tk.StringVar()
        self.varOpt23.set(self.OptionList23[0])
        self.opt23 = tk.OptionMenu(self.frame2, self.varOpt23, *self.OptionList23)
        if globals.nPlatform == 1:
            self.opt23.config(width=10)
        else:
            self.opt23.config(width=5)
        self.opt23.config(anchor=tk.W)
        self.opt23.grid(row=2, column=1, sticky=tk.W)

        # 3rd frame for scanning setting
        self.frame3 = tk.LabelFrame(self.root, text="Scanning Setting",
                            labelanchor="nw")
        self.frame3.place(x=10, y=170, height=105, width=400)

        self.lblScanTimeout = tk.Label(
            self.frame3, text="Scanning Timeout:")
        self.lblScanTimeout.grid(row=0, column=0, sticky=tk.E, ipadx=5)

        self.lblRefreshPeriod = tk.Label(
            self.frame3, text="Refresh Period:")
        self.lblRefreshPeriod.grid(row=1, column=0, sticky=tk.E, ipadx=5)
        if globals.nPlatform == 1:
            self.btnChangeAll = tk.Button(self.frame2, text="Change All",
                                    width=10, command=self.onChangeAll)
            self.btnChangeAll.grid(row=3, column=0, padx=10, sticky=tk.W)

            self.btnChangeSelected = tk.Button(
                self.frame2, text="Change Selected", width=13 , command=self.onChangeSelected)
            self.btnChangeSelected.grid(row=3, column=1, ipadx=1, sticky=tk.W)
        else:
            self.btnChangeAll = tk.Button(self.frame2, text="Change All",
                                    width=7, command=self.onChangeAll)
            self.btnChangeAll.grid(row=3, column=0, sticky=tk.W)

            self.btnChangeSelected = tk.Button(
                self.frame2, text="Change Selected", width=10 , command=self.onChangeSelected)
            self.btnChangeSelected.grid(row=3, column=1, sticky=tk.W)


        self.varScanTimeout = tk.StringVar()
        self.varScanTimeout.set(globals.myConfig.Scanning)
        self.entryScanTimeout = tk.Entry(
            self.frame3, textvariable=self.varScanTimeout, width=4)  # , commmand=onScanPeriod)
        self.entryScanTimeout.grid(row=0, column=1, padx=5, pady=5)

        def onConfirmChange():
            globals.myConfig.Scanning = self.varScanTimeout.get()
            globals.myConfig.Refresh = self.varRefreshPeriod.get()
            globals.action.counter = int(globals.myConfig.Refresh)*60
            globals.logger.info("Change scan timeout = %d, refresh time in seconds = %d", int(
                globals.myConfig.Scanning), int(globals.myConfig.Refresh))


        self.varRefreshPeriod = tk.StringVar()
        self.varRefreshPeriod.set(globals.myConfig.Refresh)
        self. entryRefreshPeriod = tk.Entry(
            self.frame3, textvariable=self.varRefreshPeriod, width=4)
        self.entryRefreshPeriod.grid(row=1, column=1, padx=5, pady=5)

        self.lblSeconds = tk.Label(
            self.frame3, text="Second(s)")
        self.lblSeconds.grid(row=0, column=2, sticky=tk.W)

        self.lblMinites = tk.Label(
            self.frame3, text="Minute(s)")
        self.lblMinites.grid(row=1, column=2, sticky=tk.W)

        self.btnConfirm = tk.Button(self.frame3, text="Confirm Change", width=9,
                            command=onConfirmChange)
        self.btnConfirm.grid(row=0, column=3, rowspan=2, ipadx=5, ipady=15)

        # frame4
        self.frame4 = tk.LabelFrame(self.root, text="IP Configuration",
                            labelanchor="nw")
        if globals.nPlatform == 1:
            self.frame4.place(x=10, y=290, height=170, width=400)
        else:
            self.frame4.place(x=10, y=280, height=165, width=400)
        self.varIPMode = tk.StringVar()
        self.varIPMode.set(0)
        self.radioIPDHCP = tk.Radiobutton(self.frame4, text='DHCP',
                                    var=self.varIPMode, value=0) # , command=onRadioDHCP)
        self.radioIPDHCP.grid(column=0, row=0, sticky='w')
        self.radioIPStatic = tk.Radiobutton(self.frame4, text='Static',
                                    var=self.varIPMode, value=1) # , command=onRadioStatic)
        self.radioIPStatic.grid(column=1, row=0, sticky='w')
        self.lblIP = tk.Label(self.frame4, text="IP:")
        self.lblIP.grid(row=1, column=0, sticky='e', padx=5)
        self.lblNetmask = tk.Label(self.frame4, text="Netmask:")
        self.lblNetmask.grid(row=2, column=0, sticky='e', padx=5)
        self.lblGateway = tk.Label(self.frame4, text="Gateway:")
        self.lblGateway.grid(row=3, column=0, sticky='e', padx=5)
        self.lblDNS = tk.Label(self.frame4, text="DNS:")
        self.lblDNS.grid(row=4, column=0, sticky='e', padx=5)
        self.varIP = tk.StringVar()
        self.varIP.set("192.168.66.66")
        vcmd1 = self.root.register(self.validate)
        self.ipaddr = tk.Entry(self.frame4, textvariable=self.varIP, width=20, state="disabled")
                        #validate='key', validatecommand=(self.vcmd1, '%P'))
        self.ipaddr.grid(row=1, column=1)

        self.varNetmask = tk.StringVar()
        self.varNetmask.set("255.255.255.0")
        self.vcmd1 = self.root.register(self.validate)
        self.netmask = tk.Entry(self.frame4, textvariable=self.varNetmask, width=20, state="disabled")
                        #validate='key', validatecommand=(vcmd1, '%P'), )
        self.netmask.grid(row=2, column=1)

        self.varGateway = tk.StringVar()
        self.varGateway.set("192.168.66.1")
        self.vcmd1 = self.root.register(self.validate)
        self.gateway = tk.Entry(self.frame4, textvariable=self.varGateway, width=20, state="disabled",
                        validate='key') # , validatecommand=(vcmd1, '%P'))
        self.gateway.grid(row=3, column=1)

        self.varDNS = tk.StringVar()
        self.varDNS.set("8.8.8.8")
        self.vcmd1 = self.root.register(self.validate)
        self.dns = tk.Entry(self.frame4, textvariable=self.varDNS, width=20,
                    validate='key', state="disabled") # validatecommand=(vcmd1, '%P'), )
        self.dns.grid(row=4, column=1)

        if globals.nPlatform == 1:
            self.btnChangeIP = tk.Button(self.frame4, text="Change IP", width=15,
                                    state="disabled") # , command=onChangeIP, )
            self.btnChangeIP.grid(row=0, column=3, padx=10)

            self.btnDNS8888 = tk.Button(self.frame4, text="DNS=8.8.8.8", width=15,
                                state="normal") #command=onDNS8888, )
            self.btnDNS8888.grid(row=4, column=3, padx=10)
        else:
            self.btnChangeIP = tk.Button(self.frame4, text="Change IP",
                                    state="disabled") # command=onChangeIP, )
            self.btnChangeIP.grid(row=0, column=3)

            self.btnDNS8888 = tk.Button(self.frame4, text="DNS=8.8.8.8",
                                state="normal") # command=onDNS8888, )
            self.btnDNS8888.grid(row=4, column=3)

        # frame5
        self.frame5 = tk.LabelFrame(self.root, text="Miner Configuration",
                            labelanchor="nw")

        if globals.nPlatform == 1:
            self.frame5.place(x=10, y=460, height=55, width=400)
        else:
            self.frame5.place(x=10, y=450, height=55, width=400)
        self.lblClock = tk.Label(self.frame5, text="OSC Clock:")
        self.lblClock.grid(row=0, column=0, sticky='e', padx=5)

        self.OptionList3 = globals.myConfig.Clock

        self.varOpt3 = tk.StringVar()

        self.varOpt3.set(self.OptionList3[1])
        self.opt3 = tk.OptionMenu(self.frame5, self.varOpt3, *self.OptionList3)
        self.opt3.config(anchor=tk.W)
        self.opt3.config(width=15)
        self.opt3.grid(row=0, column=1)

        self.btnChangeMC = tk.Button(self.frame5, text="Change Clock") #,
                                #command=lambda: onChangeMC(varOpt3.get()))
        self.btnChangeMC.grid(row=0, column=2, sticky=tk.W)


        # frame61
        self.frame61 = tk.LabelFrame(self.root, text="Miner Control", labelanchor="nw")
        if globals.nPlatform == 1:
            self.frame61.place(x=10, y=520, height=290, width=130)
        else:
            self.frame61.place(x=10, y=510, height=285, width=130)

        if globals.nPlatform == 1:
            myPadx = 20
            myWidth = 12
            self.btnStart = tk.Button(self.frame61, text="Start",
                                width=myWidth) #, command=onStart)
            self.btnStart.grid(row=0, column=0, padx=myPadx, pady=1)
            self.btnStop = tk.Button(self.frame61, text="Stop",
                                width=myWidth) #, command=onStop)
            self.btnStop.grid(row=1, column=0, padx=myPadx, pady=1)
            self.btnReboot = tk.Button(self.frame61, text="Reboot",
                                width=myWidth) #, command=onReboot)
            self.btnReboot.grid(row=2, column=0, padx=myPadx, pady=1)
            self.btnFind = tk.Button(self.frame61, text="Find (LED ON)",
                                width=myWidth)# , command=onFindOn)
            self.btnFind.grid(row=3, column=0, padx=myPadx, pady=1)
            self.btnFindOff = tk.Button(
                self.frame61, text="Find (LED OFF)", width=myWidth) #, command=onFindOff)
            self.btnFindOff.grid(row=4, column=0, padx=myPadx, pady=1)
            self.btnFReset = tk.Button(self.frame61, text="Load Default",
                                width=myWidth) #, command=onLoadDefault)
            self.btnFReset.grid(row=5, column=0, padx=myPadx, pady=1)
        else:
            myPadx = 9
            self.btnStart = tk.Button(self.frame61, text="Start", width=8) #, command=onStart)
            self.btnStart.grid(row=0, column=0, padx=myPadx)
            self.btnStop = tk.Button(self.frame61, text="Stop", width=8) #, command=onStop)
            self.btnStop.grid(row=1, column=0, padx=myPadx)
            self.btnReboot = tk.Button(self.frame61, text="Reboot",
                                width=8) #, command=onReboot)
            self.btnReboot.grid(row=2, column=0, padx=myPadx)
            self.btnFind = tk.Button(self.frame61, text="Find (LED ON)",
                                width=8) #, command=onFindOn)
            self.btnFind.grid(row=3, column=0, padx=myPadx)
            self.btnFindOff = tk.Button(
                self.frame61, text="Find (LED OFF)", width=8) #, command=onFindOff)
            self.btnFindOff.grid(row=4, column=0, padx=myPadx)
            self.btnFReset = tk.Button(self.frame61, text="Load Default",
                                width=8) #, command=onLoadDefault)
            self.btnFReset.grid(row=5, column=0, padx=myPadx)


            # frame62
            self.frame62 = tk.LabelFrame(
                self.root, text="Export and Change Fan Duty", labelanchor="nw")
            self.frame62.place(x=150, y=510, height=285, width=260)

            self.lblPr8XFan = tk.Label(self.frame62, text="PR_8X Fan Duty(%)", width=14)
            self.lblPr8XFan.grid(row=6, column=0, columnspan=2)
            self.OptionListPr8xFanDuty = globals.myConfig.pr_8x_fan_duty
            self.varOptPr8XFan = tk.StringVar()
            self.varOptPr8XFan.set(self.OptionListPr8xFanDuty[3])
            self.Opt621 = tk.OptionMenu(self.frame62, self.varOptPr8XFan, *self.OptionListPr8xFanDuty)
            self.Opt621.config(width=12)
            self.Opt621.grid(row=7, column=0, columnspan=2)
            self.btnPr8XFan = tk.Button(self.frame62, text="Change Fan Duty",
                                command=onChanePR8XFAN, width=14)
            self.btnPr8XFan.grid(row=8, column=0, columnspan=2)

        self.varhr1 = tk.StringVar()
        self.varhr1.set(0)
        self.varmin1 = tk.StringVar()
        self.varmin1.set(0)
        self.varhr2 = tk.StringVar()
        self.varhr2.set(0)
        self.varmin2 = tk.StringVar()
        self.varmin2.set(0)

        def onCopy1():
            onCopy(1)

        def onCopy2():
            onCopy(2)

        def onCopy3():
            onCopy(3)

        def onCopy(nCopy):
            ##global varhr1
            ##global varhr2
            ##global varmin1
            ##global varmin2
            if nCopy < 3 and len(self.tvWorker.get_children()) == 0:
                messagebox.showwarning(
                    title="Warning", message="No data in the tree view.")
                return
            if nCopy == 1 and len(self.tvWorker.selection()) == 0:
                messagebox.showwarning(
                    title="Warning", message="Please double click one miner to copy log.")
                return
            if nCopy == 2 and len(self.tvWorker.selection()) == 0:
                messagebox.showwarning(
                    title="Warning", message="Please select at least one miner to copy log.")
                return
            lstServerID = []
            if nCopy == 1 or nCopy == 2:
                for item in self.tvWorker.selection():
                    item_text = self.tvWorker.item(item, "values")
                    if varServerMode.get() == '0':
                        lstServerID.append(
                            item_text[self.tvWorker['columns'].index("ServerID")])
                    else:
                        lstServerID.append(
                            item_text[self.tvWorker['columns'].index("MAC")])
            elif nCopy == 3:
                for item in self.tvWorker.get_children():
                    item_text = self.tvWorker.item(item, "values")
                    if varServerMode.get() == '0':
                        lstServerID.append(
                            item_text[self.tvWorker['columns'].index("ServerID")])
                    else:
                        lstServerID.append(
                            item_text[self.tvWorker['columns'].index("MAC")])

            conn = ConnectToDB()
            cursor = GetCursorDB(conn)
            d2_tmp = datetime.strptime(self.varD2.get(), '%Y-%m-%d')
            d2hm_tmp = d2_tmp.replace(
                hour=int(varhr2.get()), minute=int(self.varmin2.get()))
            d2hm_str = d2hm_tmp.strftime('%Y-%m-%d %H:%M')
            d1_tmp = datetime.strptime(self.varD1.get(), '%Y-%m-%d')
            d1hm_tmp = d1_tmp.replace(
                hour=int(varhr1.get()), minute=int(self.varmin1.get()))
            d1hm_str = d1hm_tmp.strftime('%Y-%m-%d %H:%M')
            WriteWorkerToFile(cursor, d1hm_str, d2hm_str, lstServerID, nCopy)
            CloseDB(conn, cursor)


        d2 = datetime.now() + timedelta(1)
        d1 = d2 - timedelta(days=5)
        self.varD2 = tk.StringVar()
        self.varD1 = tk.StringVar()
        self.varServerID = tk.StringVar()
        self.varServerID.set("")

        if globals.nPlatform == 1:
            mypady = 4
            mywidth = 3
            self.btnCopyAll = tk.Button(self.frame62, text="Export Time Between:",
                                command=onCopy3, width=23)
            self.btnCopyAll.grid(row=0, column=0, columnspan=2)
            self.lblcal1 = tk.Label(self.frame62, text="From:", width=3,
                            anchor="e", padx=5, pady=mypady)
            self.lblcal1.grid(row=1, column=0, ipadx=5)
            self.lblcal2 = tk.Label(self.frame62, text="To:", width=3,
                            anchor="e", padx=5, pady=mypady)
            self.lblcal2.grid(row=2, column=0, ipadx=5)
            self.cal1 = DateEntry(self.frame62, setmode='day',
                            date_pattern='yyyy-MM-dd', year=d1.year, month=d1.month, day=d1.day,
                            background="white", disabledbackground="gray", bordercolor="white",
                            headersbackground="white", normalbackground="white", foreground='black',
                            normalforeground='blue', headersforeground='black', anchor="e", textvariable=varD1, width=15, padx=5, pady=mypady)
            self.cal1.grid(row=1, column=1, padx=5)
            self.cal2 = DateEntry(self.frame62, setmode='day',
                            date_pattern='yyyy-MM-dd', year=d2.year, month=d2.month, day=d2.day,
                            background="white", disabledbackground="gray", bordercolor="white",
                            headersbackground="white", normalbackground="white", foreground='black',
                            normalforeground='blue', headersforeground='black', anchor="e", textvariable=varD2, width=15, padx=5, pady=mypady)
            self.cal2.grid(row=2, column=1, padx=5)
            self.hr1 = tk.Spinbox(self.frame62, textvariable=varhr1, width=mywidth, from_=0, to=23,
                            fg="black", bg='white').grid(row=1, column=2)
            self.min1 = tk.Spinbox(self.frame62, text=varmin1, width=mywidth, from_=0, to=59,
                            fg="black", bg='white').grid(row=1, column=4)
            self.hr2 = tk.Spinbox(self.frame62, textvariable=varhr2, width=mywidth, from_=0, to=23,
                            fg="black", bg='white').grid(row=2, column=2)
            self.min2 = tk.Spinbox(self.frame62, text=varmin2, width=mywidth, from_=0, to=59,
                            fg="black", bg='white').grid(row=2, column=4)

            self.btnCopySelected = tk.Button(self.frame62, text="Export Selected Workers",
                                        command=onCopy2, width=23)
            self.btnCopySelected.grid(row=3, column=0, columnspan=2, pady=10)

            self.btnCopy = tk.Button(self.frame62, text="Export ServerID =",
                                command=onCopy1, width=23)
            self.btnCopy.grid(row=4, column=0, columnspan=2)
            self.ServerID = tk.Entry(
                self.frame62, textvariable=varServerID, width=24, justify=tk.CENTER)
            self.ServerID.grid(row=5, column=0, columnspan=2)
        else:
            mywidth = 2
            self.btnCopyAll = tk.Button(self.frame62, text="Export Time between:",
                                command=onCopy3, width=14)
            self.btnCopyAll.grid(row=0, column=0, columnspan=2)
            self.lblcal1 = tk.Label(self.frame62, text="From", width=3, anchor="w")
            self.lblcal1.grid(row=1, column=0)
            self.lblcal2 = tk.Label(self.frame62, text="To", width=3, anchor="w")
            self.lblcal2.grid(row=2, column=0)
            self.cal1 = DateEntry(self.frame62, selectmode='day',
                            date_pattern='yyyy-MM-dd', year=d1.year, month=d1.month, day=d1.day,
                            background="green", disabledbackground="gray", bordercolor="white",
                            headersbackground="white", normalbackground="white", foreground='black',
                            normalforeground='blue', headersforeground='black', anchor="e", textvariable=self.varD1)
            self.cal1.grid(row=1, column=1)
            self.cal2 = DateEntry(self.frame62, selectmode='day',
                            date_pattern='yyyy-MM-dd', year=d2.year, month=d2.month, day=d2.day,
                            background="green", disabledbackground="gray", bordercolor="white",
                            headersbackground="white", normalbackground="white", foreground='black',
                            normalforeground='blue', headersforeground='black', anchor="e", textvariable=self.varD2)
            self.cal2.grid(row=2, column=1)
            self.hr1 = tk.Spinbox(self.frame62, textvariable=self.varhr1, width=mywidth, from_=0, to=23,
                            fg="black", bg='white').grid(row=1, column=2)
            self.min1 = tk.Spinbox(self.frame62, text=self.varmin1, width=mywidth, from_=0, to=59,
                            fg="black", bg='white').grid(row=1, column=4)
            self.hr2 = tk.Spinbox(self.frame62, textvariable=self.varhr2, width=mywidth, from_=0, to=23,
                            fg="black", bg='white').grid(row=2, column=2)
            self.min2 = tk.Spinbox(self.frame62, text=self.varmin2, width=mywidth, from_=0, to=59,
                            fg="black", bg='white').grid(row=2, column=4)

            self.btnCopySelected = tk.Button(self.frame62, text="Export Selected Workers",
                                        command=onCopy2, width=14)
            self.btnCopySelected.grid(row=3, column=0, columnspan=2, pady=10)

            self.btnCopy = tk.Button(self.frame62, text="Export ServerID =",
                                width=14, command=onCopy1)
            self.btnCopy.grid(row=4, column=0, columnspan=2)
            self.ServerID = tk.Entry(
                self.frame62, textvariable=self.varServerID, width=17, justify=tk.CENTER)
            self.ServerID.grid(row=5, column=0, columnspan=2)

        if globals.nPlatform == 1:
            self.lblPr8XFan = tk.Label(self.frame62, text="PR_8X Fan Duty(%)", width=23)
            self.lblPr8XFan.grid(row=6, column=0, columnspan=2)
            self.OptionListPr8xFanDuty = globals.myConfig.pr_8x_fan_duty
            self.varOptPr8XFan = tk.StringVar()
            self.varOptPr8XFan.set(OptionListPr8xFanDuty[3])
            self.Opt621 = tk.OptionMenu(self.frame62, varOptPr8XFan, *OptionListPr8xFanDuty)
            self.Opt621.config(width=18)
            self.Opt621.grid(row=7, column=0, columnspan=2)
            self.btnPr8XFan = tk.Button(self.frame62, text="Change Fan Duty") #,
                #command=onChanePR8XFAN, width=23)
            self.btnPr8XFan.grid(row=8, column=0, columnspan=2)
        else:
            self.lblPr8XFan = tk.Label(self.frame62, text="PR_8X Fan Duty(%)", width=14)
            self.lblPr8XFan.grid(row=6, column=0, columnspan=2)
            self.OptionListPr8xFanDuty = globals.myConfig.pr_8x_fan_duty
            self.varOptPr8XFan = tk.StringVar()
            self.varOptPr8XFan.set(self.OptionListPr8xFanDuty[3])
            self.Opt621 = tk.OptionMenu(self.frame62, self.varOptPr8XFan, *self.OptionListPr8xFanDuty)
            self.Opt621.config(width=12)
            self.Opt621.grid(row=7, column=0, columnspan=2)
            self.btnPr8XFan = tk.Button(self.frame62, text="Change Fan Duty", width=14)
                                #command=onChanePR8XFAN, )
            self.btnPr8XFan.grid(row=8, column=0, columnspan=2)

            # frame7
            self.frame7 = tk.LabelFrame(self.root, text="Miner List",
                            labelanchor="nw")
            self.frame7.place(x=420, y=170, height=625, width=800)
            self.Style = ttk.Style()
            self.Style.theme_use('clam')
            self.Style.configure("Treeview.Heading", background="light gray", foreground="black", font=(
                "Arial Bold", self.nFontSize))
            self.Style.configure("Treeview", font=("Arial", self.nFontSize), anchor=LEFT)
            # init a scrollbar
            self.sbx = tk.Scrollbar(self.frame7, orient=tk.HORIZONTAL)
            self.sby = tk.Scrollbar(self.frame7, orient=tk.VERTICAL)
            # 預設是 show="tree"顯示圖標欄， "show=headings" 不顯示圖標欄。
            self.tvWorker = ttk.Treeview(
                self.frame7, height=18, show="headings", columns=columns)
            self.tvWorker.place(relx=0.01, rely=0.01, height=568, width=757)
            #tvWorker.place(relx=0.01, rely=0.01, height=frame7.winfo_height() - 57, width=frame7.winfo_width() - 45)

            self.tvWorker.configure(yscrollcommand=self.sby.set, xscrollcommand=self.sbx.set)
            # selectmode=BROWSE，一次選擇一項，預設。selectmode=EXTENDED，次選擇多項。selectmode=NONE，無法用滑鼠執行選擇。
            self.tvWorker.configure(selectmode="extended")

            self.sby.configure(command=self.tvWorker.yview)
            self.sbx.configure(command=self.tvWorker.xview)

            self.sby.place(relx=0.965, rely=0.01, width=22, height=595)
            self.sbx.place(relx=0.01, rely=0.955, width=757, height=22)

            self.tvWorker.heading("#0", text="ID", anchor="center")
            for i in range(len(columns)):
                self.tvWorker.heading("#"+str(i+1), text=columns[i], anchor="center")
            self.tvWorker['show'] = 'tree headings'

            self.tvWorker.tag_configure('red', background='red')
            self.tvWorker.tag_configure('yellow', background='yellow')
            self.tvWorker.tag_configure('green', background='lightgreen')
            self.tvWorker.tag_configure('normal', background='white')
            self.tvWorker.tag_configure('gray', background='gray')

        def onClosing():
            globals.bLoop = False
            globals.logger.info('=== End of PowerRayEtcAP v%4.2f ===', globals.POWERRAY_ETC_VERSION)
            self.root.destroy()

        def onShow(index):
            self.tvWorker.column("#0", width=40,  stretch=False)
            for col in columns:  # 绑定函数，使表头可排序
                self.tvWorker.heading(col, text=col, command=lambda _col=col: treeview_sort_column(
                    self.tvWorker, _col, False))
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
                if globals.nPlatform == 1:
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
                    if globals.myConfig.ShowAll[col] == '0':
                        minwidth = 0
                        width = 0
                if index == 1:
                    if globals.myConfig.Show1[col] == '0':
                        minwidth = 0
                        width = 0
                if index == 2:
                    if globals.myConfig.Show2[col] == '0':
                        minwidth = 0
                        width = 0
                if index == 3:
                    if globals.myConfig.Show3[col] == '0':
                        minwidth = 0
                        width = 0
                if index == 4:
                    if globals.myConfig.Show4[col] == '0':
                        minwidth = 0
                        width = 0
                if index == 5:
                    if globals.myConfig.Show5[col] == '0':
                        minwidth = 0
                        width = 0
                self.tvWorker.column(col, minwidth=minwidth, width=width, stretch=False)
        

        def onShowAll():
            onShow(0)
            if globals.myConfig.bScan:
                self.btnShowAll.config(fg="blue")
                self.btnShow1.config(fg="black")
                self.btnShow2.config(fg="black")
                self.btnShow3.config(fg="black")
                self.btnShow4.config(fg="black")
                self.btnShow5.config(fg="black")

        def onShow1():
            onShow(1)
            if globals.myConfig.bScan:
                self.btnShowAll.config(fg="black")
                self.btnShow1.config(fg="blue")
                self.btnShow2.config(fg="black")
                self.btnShow3.config(fg="black")
                self.btnShow4.config(fg="black")
                self.btnShow5.config(fg="black")

        def onShow2():
            onShow(2)
            if globals.myConfig.bScan:
                self.btnShowAll.config(fg="black")
                self.btnShow1.config(fg="black")
                self.btnShow2.config(fg="blue")
                self.btnShow3.config(fg="black")
                self.btnShow4.config(fg="black")
                self.btnShow5.config(fg="black")

        def onShow3():
            onShow(3)
            if globals.myConfig.bScan:
                self.btnShowAll.config(fg="black")
                self.btnShow1.config(fg="black")
                self.btnShow2.config(fg="black")
                self.btnShow3.config(fg="blue")
                self.btnShow4.config(fg="black")
                self.btnShow5.config(fg="black")

        def onShow4():
            onShow(4)
            if globals.myConfig.bScan:
                self.btnShowAll.config(fg="black")
                self.btnShow1.config(fg="black")
                self.btnShow2.config(fg="black")
                self.btnShow3.config(fg="black")
                self.btnShow4.config(fg="blue")
                self.btnShow5.config(fg="black")

        def onShow5():
            onShow(5)
            if globals.myConfig.bScan:
                self.btnShowAll.config(fg="black")
                self.btnShow1.config(fg="black")
                self.btnShow2.config(fg="black")
                self.btnShow3.config(fg="black")
                self.btnShow4.config(fg="black")
                self.btnShow5.config(fg="blue")

        if globals.nPlatform == 1:
            self.btnShowAll = tk.Button(
                self.root, text="Show All", width=10, command=onShowAll)
            self.btnShowAll.place(x=420, y=155, height=30, width=100)

            self.btnShow1 = tk.Button(
                self.root, text="Show #1", width=10, command=onShow1)
            self.btnShow1.place(x=525, y=155, height=30, width=100)

            self.btnShow2 = tk.Button(
                self.root, text="Show #2", width=10, command=onShow2)
            self.btnShow2.place(x=630, y=155, height=30, width=100)

            self.btnShow3 = tk.Button(
                self.root, text="Show #3", width=10, command=onShow3)
            self.btnShow3.place(x=735, y=155, height=30, width=100)

            self.btnShow4 = tk.Button(
                self.root, text="Show #4", width=10, command=onShow4)
            self.btnShow4.place(x=840, y=155, height=30, width=100)

            self.btnShow5 = tk.Button(
                self.root, text="Show #5", width=10, command=onShow5)
            self.btnShow5.place(x=945, y=155, height=30, width=100)

            self.btnQuit = tk.Button(self.root, text="Quit Program", width=10, command=onClosing)
            self.btnQuit.place(x=1120, y=155, height=30, width=10)
        else:
            self.btnShowAll = tk.Button(
                self.root, text="Show All", width=10, command=onShowAll)
            self.btnShowAll.place(x=420, y=137, height=30, width=100)

            self.btnShow1 = tk.Button(
                self.root, text="Show #1", width=10, command=onShow1)
            self.btnShow1.place(x=520, y=137, height=30, width=100)

            self.btnShow2 = tk.Button(
                self.root, text="Show #2", width=10, command=onShow2)
            self.btnShow2.place(x=620, y=137, height=30, width=100)

            self.btnShow3 = tk.Button(
                self.root, text="Show #3", width=10, command=onShow3)
            self.btnShow3.place(x=720, y=137, height=30, width=100)

            self.btnShow4 = tk.Button(
                self.root, text="Show #4", width=10, command=onShow4)
            self.btnShow4.place(x=820, y=137, height=30, width=100)

            self.btnShow5 = tk.Button(
                self.root, text="Show #5", width=10, command=onShow5)
            self.btnShow5.place(x=920, y=137, height=30, width=100)

            self.btnQuit = tk.Button(self.root, text="Quit Program", width=10, command=onClosing)
            self.btnQuit.place(x=1120, y=137, height=30, width=100)

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
                self.tvWorker.insert("", tk.END, text=str(i+1),
                                values=("PR_SB", "192.168.66.3", "192-168-66-3", "68:5E:6B:A0:10:34", "E2BCAA2238001403", "Mining", "NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA", 322.9, "NA", 2, "NA",
                                "NA", "NA", "NA", "NA", "stratum+tcp://asia1-etc.ethermine.org:4444", "0x57fc699ad1249f65759e1af273e26350dece1eb6", "NA", 1234, 19.5, "NA", "NA", 44.0, 40.0, "NA", "NA", "NA", "NA", "NA", "NA", "NA", "NA"), tag=myTag)

