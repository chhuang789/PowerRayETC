# Refer the following API documenets
# https://api.ethermine.org/docs/
# Generic pool API for Ethpool, Ethermine & Flypool
# Ethpool, Ethermine & Flypool provide a harmonized API for accessing all publicly available information.
# Access to the API is limited to 100 requests / 15 minutes / ip.
# All information is cached for 2 minutes so there is no point in making more frequent requests.

# Ethermine.org endpoint: https://api.ethermine.org
# Ethpool.org endpoint: http://api.ethpool.org
# Ethermine ETC endpoint: https://api-etc.ethermine.org
# Flypool Zcash endpoint: https://api-zcash.flypool.org

# All endpoints are CORS enabled.

# In this python file, we use https://api-etc.ethermine.org as the endpoint

# -*- coding: utf-8 -*-
# Version Information: 20221103-001

# ---------Imports---------
import os
import ssl
import time
import json
import http.client
import requests
# ---------End of imports---------


class EthermineApi:
    def __init__(self, logger):
        # ------------Avoid SSL error and ignore SSL Warning-------------
        requests.packages.urllib3.disable_warnings()
        ssl._create_default_https_context = ssl._create_unverified_context
        # ---------End of Avoid SSL error and ignore SSL Warning---------

        # ---------Proxy---------
        self.proxy_enable = False
        # ---------End of Proxy---------

        self.session = requests.Session()
        self.theTimeout = 10
        self.connection = None
        self.logger = logger

    # Ethermine http request
    def ETCRequest(self, strURL):
        response = None
        try:
            self.connection = http.client.HTTPSConnection(
                "api-etc.ethermine.org", 443, timeout=self.theTimeout)

            if (self.connection):
                response = self.session.get(strURL, verify=False)
            else:
                self.logger.error("https connection failed")
        except Exception as e:
            self.logger.error(e)
            return response

        self.logger.debug(
            "request=%s response=%d", strURL, response.status_code)
        return response

    # getWorkerCurrentStats http request
    def getWorkerCurrentStats(self, strMiner, strIP='', strWorker=''):
        self.miner = strMiner
        self.IP = strIP
        if strWorker == '':
            if strIP != '':
                strWorker = strIP.replace(".", "-")
        self.worker = strWorker
        self.logger.debug(
            "Get the current status of miner(%s) and workder(%s) or IP(%s)", self.miner, self.IP, self.worker)
        self.url = "https://api-etc.ethermine.org/miner/" + \
            self.miner + "/worker/" + self.worker + "/currentStats"
        # https://api-etc.ethermine.org/miner/20c0ac4e73ed4db87fef692991c0f4becff93cbc/worker/<worker>/currentStats
        # https://api-etc.ethermine.org/miner/57fc699ad1249f65759e1af273e26350dece1eb6/worker/<worker>/currentStats
        #self.proxy_enable = False
        # if (self.connection == None):
        #    self.setProxy()
        timeString = ''
        strmegaHashRate = ''
        response = self.ETCRequest(self.url)
        if (response.status_code == 200):
            json_Body = json.loads(response.text)
            if json_Body['status'] == 'OK':
                dictData = json_Body['data']
                if (str(dictData) != 'NO DATA'):
                    #json_data = json.loads(result.text)
                    self.logger.info("response worker=%s", self.worker)
                    time_stamp = dictData['time']
                    struct_time = time.localtime(time_stamp)
                    timeString = time.strftime(
                        "%Y-%m-%d %H:%M:%S", struct_time)
                    self.logger.info("response time=%s", timeString)
                    megaHashRate = dictData['currentHashrate'] / 1000000
                    nPos = str(megaHashRate).find('.')
                    if nPos < 0:
                        strmegaHashRate = str(megaHashRate)
                    elif len(str(megaHashRate)) >= nPos + 3:
                        strmegaHashRate = str(megaHashRate)[0:nPos+3]
                    elif len(str(megaHashRate)) >= nPos + 2:
                        strmegaHashRate = str(megaHashRate)[0:nPos+2]
                    else:
                        strmegaHashRate = str(megaHashRate)[0:nPos]
                    self.logger.info(
                        "response current Hashrate=%s M/s", strmegaHashRate)
        self.logger.info("return time=%s, HashRate=%s M/s",
                         timeString, strmegaHashRate)
        return timeString, strmegaHashRate


'''
def main():
    # create logger
    if not os.path.exists("log"):
        os.makedirs("log")
    # Load logging.conf
    logging.config.fileConfig('logging.conf')
    console_handler = logging.StreamHandler()
    logger = logging.getLogger('PowerRayETC')

    myEthermineApi = EthermineApi(logger)
    #response = myEthermineApi.getWorkerCurrentStats("57fc699ad1249f65759e1af273e26350dece1eb6", strIP='', strWorker="192-168-66-147")
    strTime, strHashRateMs = myEthermineApi.getWorkerCurrentStats("20c0ac4e73ed4db87fef692991c0f4becff93cbc", strIP='192.168.66.147')
    logger.debug("%s %s M/s", strTime, strHashRateMs)
    strTime, strHashRateMs = myEthermineApi.getWorkerCurrentStats("57fc699ad1249f65759e1af273e26350dece1eb6", strIP='192.168.66.139')
    logger.debug("%s %s M/s", strTime, strHashRateMs)
    strTime, strHashRateMs = myEthermineApi.getWorkerCurrentStats("20c0ac4e73ed4db87fef692991c0f4becff93cbc", strIP='', strWorker="192-168-66-147")
    logger.debug("%s %s M/s", strTime, strHashRateMs)
    strTime, strHashRateMs = myEthermineApi.getWorkerCurrentStats("57fc699ad1249f65759e1af273e26350dece1eb6", strIP='', strWorker="192-168-66-139")
    logger.debug("%s %s M/s", strTime, strHashRateMs)
    # https://api-etc.ethermine.org/miner/20c0ac4e73ed4db87fef692991c0f4becff93cbc/worker/192-168-66-147/currentStats
    # https://api-etc.ethermine.org/miner/57fc699ad1249f65759e1af273e26350dece1eb6/worker/192-168-66-139/currentStats
    # https://api-etc.ethermine.org/miner/:20c0ac4e73ed4db87fef692991c0f4becff93cbc/workers
    # https://api-etc.ethermine.org/miner/:57fc699ad1249f65759e1af273e26350dece1eb6/workers
    exit 

if __name__ == "__main__":
    main()
'''
