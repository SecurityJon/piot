#Controlling Class. This runs controlling functionsfolder

#############################################################################
#   This script controls the entire project
#############################################################################
import random
import string
import time
import logging
import sys
import threading

from functions import create_wifi_access_points as createap, tshark_listening as tshark, nmap as nmap, functions as functions
from attacks.mitm import mymitmproxy as mitmproxy
import config as config

from rich import print
from rich.logging import RichHandler

# Get settings
tempDirectory = config.getTempStorageDirectory()
wirelessInterfaceNameForManagement = config.getManagementInterface()
wirelessAccessPointSSIDForManagement = config.getManagementSSID()
wirelessAccessPointPasswordForManagement = config.getManagementPSK()
wirelessAccessPointSSIDForIOT = config.getIOTSSID()
wirelessAccessPointPasswordForIOT = config.getIOTPSK()

wirelessAccessPointIPForIOT = config.getIOTInterfaceGatewayIPAddress()
wirelessAccessPointIPForManagement = config.getManagementInterfaceGatewayIPAddress()


def setupLoggingAndConsole():
####################################
# Setting up logging and console output
####################################
    global log
    #Standard logging
    logfile = tempDirectory + "logfile_" + ''.join(random.choice(string.ascii_lowercase) for i in range(16))
    loglevel = config.getMainLoggingLevel()

    logging.basicConfig(
        level=loglevel,
        #format='%(asctime)s  %(process)-7s %(module)-20s %(message)s',
        format='%(message)s',
        datefmt='%d/%m/%Y %H:%M:%S',
        handlers=[RichHandler(show_time=False, show_path=False, rich_tracebacks=True)]
        )
    log = logging.getLogger("rich")

def killStuckProcesses():    
    ####################################
    # Kill existing hung processes
    ####################################
    log.debug("Killing hung processes")
    functions.killLegacyProcess("tshark")
    functions.killLegacyProcess("dhcpd")
    functions.killLegacyProcess("hostapd")
    functions.killLegacyProcess("mitmdump")
    functions.killLegacyProcess("nmap")

def prepareInterfaces():
    ####################################
    # Getting interfaces ready
    ####################################
    global wirelessInterfaceName
    global routedInterfaceName

    global NetworkManagerWasRunning
    NetworkManagerWasRunning = functions.wasNetworkManagerRunningKillItIfSo()
    if NetworkManagerWasRunning == True:
        log.debug("Killing NetworkManager")
    routedInterfaceName = functions.getRoutedInterfaceName()
    log.debug("Internet Interface {}".format(routedInterfaceName))
    wirelessInterfaceName = functions.getWirelessInterfaceName(routedInterfaceName)
    log.debug("IOT Interface {}".format(wirelessInterfaceName))
    log.debug("Unblocking Wifi")
    functions.unblockWiFi()
    log.debug("Restarting Interface {}".format(wirelessInterfaceName))
    functions.restartWirelessInterface(wirelessInterfaceName)
    log.debug("Changing MAC Address")
    functions.changeMacAddress(wirelessInterfaceName)
    log.debug("Deleting NAT rules")
    createap.deleteNATRulesForIPTables()

def createConfigFiles():
    ####################################
    # Creating Config Files
    ####################################
    #HostAPD
    tempHostAPDDDirectory = functions.makeTemporaryDirectories(tempDirectory, "pwnpidir")
    global hostAPDConfigFile
    hostAPDConfigFile = tempHostAPDDDirectory + "hostapd_" + ''.join(random.choice(string.ascii_lowercase) for i in range(16))
    createap.createHostAPDFileForIOT(wirelessInterfaceName, hostAPDConfigFile, wirelessAccessPointSSIDForIOT, wirelessAccessPointPasswordForIOT, wirelessInterfaceNameForManagement, wirelessAccessPointSSIDForManagement, wirelessAccessPointPasswordForManagement)
    log.debug("HostAPD config file created at {}".format(hostAPDConfigFile))

    #DHCPD
    tempDHCPDDirectory = functions.makeTemporaryDirectories(tempDirectory, "pwnpidir")
    global dhcpdConfigFile
    dhcpdConfigFile = tempDHCPDDirectory + "dhcpd_" + ''.join(random.choice(string.ascii_lowercase) for i in range(16))
    createap.createDHCPLeaseFileForIOT(dhcpdConfigFile)
    log.debug("DHCPD config file created at {}".format(dhcpdConfigFile))


    tempDHCPLeasesDirectory = functions.makeTemporaryDirectories(tempDirectory, "pwnpidir")
    global dhcpdLeaseFilePath
    dhcpdLeaseFilePath = tempDHCPLeasesDirectory + "dhcpLeases_" + ''.join(random.choice(string.ascii_lowercase) for i in range(16))    
    functions.makeTemporaryFiles(dhcpdLeaseFilePath)
    log.debug("DHCPD leases file created at {}".format(dhcpdLeaseFilePath))

def setupIPTablesAndRouting():
    ####################################
    # Setting up IPTables
    ####################################
    log.debug("Turning on Network Forwarding")
    createap.forwardIPTraffic()
    log.debug("Flushing IPTables")
    createap.deleteNATRulesForIPTables()
    log.debug("Adding NAT rules")
    createap.createNATRulesForIPTables(wirelessInterfaceName, routedInterfaceName)

def enableHOSTAPD():
    ####################################
    # Turning on HostAPD
    ####################################
    #Create HOSTAPD output file
    hostAPDLogDirectory = functions.makeTemporaryDirectories(tempDirectory, "pwnpidir")
    hostapdlogFilePath = hostAPDLogDirectory + "hostapdlog_" + ''.join(random.choice(string.ascii_lowercase) for i in range(16))
    log.debug("HostAPD coming Up, sleeping for 20 seconds")
    global hostAPDProcess
    hostAPDProcess = createap.bringUpHostAPD(hostAPDConfigFile, hostapdlogFilePath)
    # Sleep for 20 seconds to give hostapd enough time to actually start
    for sleepyloop in range(20):
      time.sleep(1)

    #Check HostAPD has actually started, and there are no issues
    try:
        hostAPDpoll = hostAPDProcess.poll()
        if hostAPDpoll is not None:
            # Host APD has exited for some reason
            print("HostAPD exited for some reason, check the log at {}".format(hostapdlogFilePath))
            quit()
    except Exception as theException:
        # Host APD has exited for some reason
        print("HostAPD exited for some reason, check the log at {}".format(hostapdlogFilePath))
        quit()
      
    log.debug("Assigning IP to IOT Adaptor")
    global iotAccessPointIPAddress
    iotAccessPointIPAddress = createap.assignIPAddressToIOTAdaptor(wirelessInterfaceName)
    log.debug("Assigning IP to Management Adaptor")
    global managementAccessPointIPAddress
    managementAccessPointIPAddress = createap.assignIPAddressToManagementAdaptor(wirelessInterfaceNameForManagement)
    
def enableDHCPD():
    #First I had to remove apparmor to get DHCPD working, then reboot to clear
    # sudo apt remove apparmor
    log.debug("Starting DHCP on adaptor")
    global dhcpdProcess
    dhcpdProcess = createap.startDHCPD(dhcpdConfigFile, dhcpdLeaseFilePath, wirelessInterfaceName, wirelessInterfaceNameForManagement)

def startTShark():
    ####################################
    # Listen for traffic
    ####################################
    tempTSharkDirectory = functions.makeTemporaryDirectories(tempDirectory, "pwnpidir")
    global tsharkfilepath
    tsharkfilepath = tempTSharkDirectory + "tshark_" + ''.join(random.choice(string.ascii_lowercase) for i in range(16)) + '.pcap'
    log.debug("TShark PCAP file being logged at {}".format(tsharkfilepath))
    log.debug("Kicking off TShark Listening")
    global tsharkProcess
    tsharkProcess = tshark.kickOffTShark(wirelessInterfaceName, tsharkfilepath)

def waitforIPAddressAcquisition():
    # Wait for the IOT device to get an IP address
    log.debug("Waiting for IOT Device to acquire an IP")
    global iotDHCPAddress
    iotDHCPAddress = functions.getIOTDHCPAddress(dhcpdLeaseFilePath)
    while iotDHCPAddress == "":
      iotDHCPAddress = functions.getIOTDHCPAddress(dhcpdLeaseFilePath)
      time.sleep(1)
    log.debug("IOT Device aquired IP {}".format(iotDHCPAddress))
    return iotDHCPAddress

def checkforIPAddressAcquisition():
    if not 'iotDHCPAddress' in globals():
        isthisAnIPAddress = functions.getIOTDHCPAddress(dhcpdLeaseFilePath)
        if isthisAnIPAddress == None:
            if not 'firstPromptThatIPHasNotBeenSeenIsDone' in globals():
                global firstPromptThatIPHasNotBeenSeenIsDone
                firstPromptThatIPHasNotBeenSeenIsDone = True
                log.debug("IP Address has not yet been seen")
            return None
        else:
            log.debug("IP Address seen is {}".format(isthisAnIPAddress))
            global iotDHCPAddress
            iotDHCPAddress = isthisAnIPAddress
            return isthisAnIPAddress
    else:
        return iotDHCPAddress


    #Method to get the MAC/IP/Vendor of an IOT Device
def getIOTDeviceDetails():
    return functions.getIOTDHCPAddressFullDetails(dhcpdLeaseFilePath)

    ####################################
    # Kick off NMAP
    ####################################
def startNMAP():
    #Check if nmap has been started, if it has, don't start it again
    if not 'nmapStarted' in globals():
        global nmapStarted
        nmapStarted = True
        #Just wait a second for the device to actually get it's IP!
        log.info("Beginning NMAP against device {}".format(iotDHCPAddress))
        time.sleep(2)
        tempNMAPDirectory = functions.makeTemporaryDirectories(tempDirectory, "pwnpidir")
        global nmapResultsPath
        nmapResultsPath = tempNMAPDirectory + "nmap_" + ''.join(random.choice(string.ascii_lowercase) for i in range(16))
        log.debug("NMAP results for {}, logged at {}".format(iotDHCPAddress, nmapResultsPath))
        threading.Thread(target=nmapStartingThread, args=(), daemon=True).start()

#Threaded version as NMAP blocks until it's completed
def nmapStartingThread():
    global nmapProcess
    nmapProcess = nmap.kickOffNMAP(iotDHCPAddress, nmapResultsPath)


def getNMAPResults():
    if 'nmapResultsPath' in globals():
        #Removed for spamming log files
        #log.debug("Retrieving NMAP results from {} for {}".format(nmapResultsPath, iotDHCPAddress))
        return nmap.getNMAPresults(nmapResultsPath)
    
#Check the status of the nmap process
def checkNMAP():
    #Check if nmap has been started at some point
    if 'nmapStarted' in globals():
        if 'nmapFinished' in globals():
            return "finished"
        else:
            #Check the process, has it exited?
            if 'nmapProcess' in globals():
                nmapPoll = nmapProcess.poll()
                if nmapPoll is not None:
                    print("NMAP process has finished")
                    global nmapFinished
                    nmapFinished = True
                    return "finished"
                else:
                    # If it's not finished it must be running
                    return "running"
            #The process is just starting up
            else:
                return "running"
    #Process hasn't started yet
    else:
        return "notstarted"

def getDNSEntriesSeen():
    global dnsEntriesSeen
    #Cache in a global variable
    dnsEntriesSeen = tshark.dnsQueries(tsharkfilepath)
    return dnsEntriesSeen

#PCAP dump can take a few seconds to parse, this returns the immediate data we have in the global cache
def getImmediateDNSEntriesSeen():
    if "dnsEntriesSeen" in globals():
        return dnsEntriesSeen
    else:
        return None

def getmDNSEntriesSeen():
    global mdnsEntriesSeen
    #Cache in a global variable
    mdnsEntriesSeen = tshark.getmDNSAdvertisements(tsharkfilepath)
    return mdnsEntriesSeen

#PCAP dump can take a few seconds to parse, this returns the immediate data we have in the global cache
def getImmediatemDNSEntriesSeen():
    if "mdnsEntriesSeen" in globals():
        return mdnsEntriesSeen
    else:
        return None


def getSNIsSeen():
    global snisSeen
    #Cache in a global variable
    snisSeen = tshark.getSNIFromTLS(tsharkfilepath)
    return snisSeen

#PCAP dump can take a few seconds to parse, this returns the immediate data we have in the global cache
def getImmediateSNIsSeen():
    if "snisSeen" in globals():
        return snisSeen
    else:
        return None


def getRawTSharkDump():
    ouraddress = wirelessAccessPointIPForIOT
    tsharkDump = tshark.getItAllMinusSomeBits(tsharkfilepath, ouraddress)
    return tsharkDump


#Returns a two dim list of unique IOT/Cloud convos
def getIOTConversations():
    deviceIP = checkforIPAddressAcquisition()
    if deviceIP is not None:
        global iotConversationsSeen
        #Cache in a global variable
        iotConversationsSeen = tshark.getConversations(tsharkfilepath, deviceIP)
        return iotConversationsSeen
    else:
        return None

#PCAP dump can take a few seconds to parse, this returns the immediate data we have in the global cache
def getImmediateIOTConversations():
    if "iotConversationsSeen" in globals():
        return iotConversationsSeen
    else:
        return None


def getImmediateCipherSuitesUsed():
    if "iotConvosAndTheirSuites" in globals():
        return iotConvosAndTheirSuites
    else:
        return None

#Check the Convos and client CipherSuites in those convos
def getCipherSuitesUsed():
    deviceIP = checkforIPAddressAcquisition()
    if deviceIP is not None:
        #Cache in a global variable
        global iotConvosAndTheirSuites
        iotConvosAndTheirSuites = tshark.getCipherSuitesPermittedByClient(tsharkfilepath, deviceIP)
        return iotConvosAndTheirSuites
    else:
        return None

def getPCAPLocation():
    return tsharkfilepath
    
####################################
# Kick off MiTM Proxy Default Mode
####################################
def startMITMProxyDefaultMode():
    #Check if any mitmproxy has been started, if it has, don't start it again
    if not 'mitmproxyStarted' in globals():
        log.info("MitmProxy Default Mode Starting")
        global mitmproxyStarted
        mitmproxyStarted = True
        tempMitmProxyDirectory = functions.makeTemporaryDirectories(tempDirectory, "pwnpidir")
        global tempMitmProxyFilePath
        tempMitmProxyFilePath = tempMitmProxyDirectory + "mitmproxy_" + ''.join(random.choice(string.ascii_lowercase) for i in range(16))
        log.debug("Random filepath for mitmproxy: {}".format(tempMitmProxyFilePath))

        #Flush all existing NAT rules, I suspect this is needed
        createap.deleteNATRulesForIPTables()    
        #Create MITM IPTables NAT rules
        log.debug("Creating new IPTables Rules")
        mitmproxy.setUpIPTablesRedirectionRules(wirelessInterfaceName, routedInterfaceName)
        #Kick off MiTM Proxy
        global mitmproxyProcess
        mitmproxyProcess = mitmproxy.kickOffMiTMProxyDefaultMode(iotAccessPointIPAddress, tempMitmProxyFilePath)
        global mitmproxyProcessDefaultModeRunning
        mitmproxyProcessDefaultModeRunning = True
        log.info("MitmProxy Default Mode Started")

    
def getMiTMProxyHTTPSConvos():
    try:
        #print(globals())
        if "tempMitmProxyFilePath" in globals():
            mitmProxyResults = mitmproxy.getHTTPSConvos(tempMitmProxyFilePath)
            return mitmProxyResults
        else:
            return []
    except Exception as theexception:
        log.error("Error getting MITMProxy convos: {}".format(theexception))
        return []
    
def checkIsMitmProxyDefaultModeRunning():
    if 'mitmproxyProcessDefaultModeRunning' in globals():    
        return True
    else:
        return False
    
def checkIsMitmProxyCloneModeRunning():
    if 'mitmproxyProcessCloneModeRunning' in globals():    
        return True
    else:
        return False
    
def checkIsMitmProxyLetsEncryptCloneModeRunning():
    if 'mitmproxyProcessLetsEncryptCloneModeRunning' in globals():    
        return True
    else:
        return False        

def killMitmProxyProcess():
    if 'mitmproxyProcess' in globals():    
        functions.killProcess(mitmproxyProcess)
        log.debug("MitmProxy Process killed")
        del globals()['mitmproxyProcess']
        if 'mitmproxyProcessDefaultModeRunning' in globals():
            del globals()['mitmproxyProcessDefaultModeRunning']
        if 'mitmproxyProcessCloneModeRunning' in globals():
            del globals()['mitmproxyProcessCloneModeRunning']
        if 'mitmproxyProcessLetsEncryptCloneModeRunning' in globals():
            del globals()['mitmproxyProcessLetsEncryptCloneModeRunning']
        if "mitmproxyStarted" in globals():
            del globals()['mitmproxyStarted']
        else:
            log.error("Cannot delete mitmproxyStarted from globals for some reason")
    #Reset the network routing to get connectivity back
    setupIPTablesAndRouting()
  
####################################
# Kick off MiTM Proxy CA/Leaf Clone mode
####################################
def startMITMProxyCloneMode():
    #Check if any mitmproxy has been started, if it has, don't start it again
    if not 'mitmproxyStarted' in globals():
        log.info("MitmProxy Clone Mode Starting")        
        global mitmproxyStarted
        mitmproxyStarted = True
        tempMitmProxyDirectory = functions.makeTemporaryDirectories(tempDirectory, "pwnpidir")
        global tempMitmProxyFilePath
        tempMitmProxyFilePath = tempMitmProxyDirectory + "mitmproxy_" + ''.join(random.choice(string.ascii_lowercase) for i in range(16))
        log.debug("Random filepath for mitmproxy: {}".format(tempMitmProxyFilePath))       
    
        #Grab DNS entries to build upon
        dnsEntriesSeen = getDNSEntriesSeen()

        #Flush all existing NAT rules, I suspect this is needed
        createap.deleteNATRulesForIPTables()
        #input("Deleted IPTables check they are empty")
        #Create MITM IPTables NAT rules
        log.debug("Creating new IPTabbles Rules")
        mitmproxy.setUpIPTablesRedirectionRules(wirelessInterfaceName, routedInterfaceName)
        #Create fake certificates
        log.debug("Generating fake certificates from previously seen DNS queries")
        fakeCertificateChainList = mitmproxy.generateAFakeCertificateChain(dnsEntriesSeen, tempMitmProxyDirectory)

        #Kick off MiTM Proxy
        global mitmproxyProcess
        log.info("MiTMProxy Clone Mode started")    
        mitmproxyProcess = mitmproxy.kickOffMiTMProxySelfCloneMode(iotAccessPointIPAddress, tempMitmProxyFilePath, fakeCertificateChainList)
        global mitmproxyProcessCloneModeRunning        
        mitmproxyProcessCloneModeRunning = True


####################################
# Kick off MiTM LetsEncrypt Clone mode
####################################
def startMITMProxyLetsEncryptCloneMode():
    #Check if any mitmproxy has been started, if it has, don't start it again
    if not 'mitmproxyStarted' in globals():
        log.info("MitmProxy LetsEncrypt Clone Mode Starting")        
        global mitmproxyStarted
        mitmproxyStarted = True
        tempMitmProxyDirectory = functions.makeTemporaryDirectories(tempDirectory, "pwnpidir")
        global tempMitmProxyFilePath
        tempMitmProxyFilePath = tempMitmProxyDirectory + "mitmproxy_" + ''.join(random.choice(string.ascii_lowercase) for i in range(16))
        log.debug("Random filepath for mitmproxy: {}".format(tempMitmProxyFilePath))       
    
        #Grab DNS entries to build upon
        dnsEntriesSeen = getDNSEntriesSeen()

        #Flush all existing NAT rules, I suspect this is needed
        createap.deleteNATRulesForIPTables()
        #Create MITM IPTables NAT rules
        log.debug("Creating new IPTabbles Rules")
        mitmproxy.setUpIPTablesRedirectionRules(wirelessInterfaceName, routedInterfaceName)
        #Create fake certificates
        log.debug("Generating fake certificates from previously seen DNS queries")
        fakeCertificateChainList = mitmproxy.generateAFakeCertificateChainForLetsEncrypt(dnsEntriesSeen, tempMitmProxyDirectory)

        #Kick off MiTM Proxy
        global mitmproxyProcess
        log.info("MiTMProxy Clone Mode started")    
        mitmproxyProcess = mitmproxy.kickOffMiTMProxyLetsEncryptCloneMode(iotAccessPointIPAddress, tempMitmProxyFilePath, fakeCertificateChainList)
        global mitmproxyProcessLetsEncryptCloneModeRunning
        mitmproxyProcessLetsEncryptCloneModeRunning = True


def endGracefully():
    #Kill Processes
    try:
        log.debug("Killing TShark Process")
        functions.killProcess(tsharkProcess)
    except(Exception):
        pass
    
    try:
        log.debug("Killing HOSTAPD Process")        
        functions.killProcess(hostAPDProcess)
    except(Exception):
        pass
    try:
        log.debug("Killing DHCPD Process")        
        functions.killProcess(dhcpdProcess)
    except(Exception):
        pass
    try:
        log.debug("Killing MITMProxy Process")        
        functions.killProcess(mitmproxyProcess)
    except(Exception):
        pass
    try:
        if NetworkManagerWasRunning == True:
            log.debug("Starting Network Manager")
            functions.startNetworkManager()
    except(Exception):
        pass

    #Delete Routes/NAT
    log.debug("Deleting NAT rules")
    createap.deleteNATRulesForIPTables()

    #Reset the Wifi to bring down the AP
    log.debug("Restarting Wifi")
    functions.restartWirelessInterface(wirelessInterfaceName)



  

