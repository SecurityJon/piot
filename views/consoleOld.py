# Console App

from rich.console import Console
from rich.progress import Progress
from rich.live import Live
from rich.table import Table

import config as config
import time
import keyboard
import logging
import threading

import config as config

#This is used for creating dummy data for testing, a dummy controller is created
standalonetestmode = config.getIsThisTestMode()
if standalonetestmode == True:
    import test.testcontroller as controller
else:
    import controller as controller


log = logging.getLogger("rich")
console = Console()

####################################
# Grab config items
####################################
wirelessAccessPointSSIDForIOT = config.getIOTSSID()
wirelessAccessPointPasswordForIOT = config.getIOTPSK()
wirelessAccessPointSSIDForManagement = config.getManagementSSID()
wirelessAccessPointPasswordForManagement = config.getManagementPSK()
wirelessAccessPointIPForIOT = config.getIOTInterfaceGatewayIPAddress()

####################################
# print to screen
####################################
log.info("")
log.info("Please connect the IOT to the following")
log.info("SSID:     {}".format(wirelessAccessPointSSIDForIOT))
log.info("Password: {}".format(wirelessAccessPointPasswordForIOT))
log.info("")
log.info("Please connect your phone to the following")
log.info("SSID:     {}".format(wirelessAccessPointSSIDForManagement))
log.info("Password: {}".format(wirelessAccessPointPasswordForManagement))

######################################################################
# DNS
######################################################################
def dnsStuffMethod():
    # TABLE
    table = Table(show_lines=True)
    table.add_column("DNS Names Seen")
    table.add_column("IP Addresses Seen")
    table.add_column("mDNS Advertisements")

    # Strings
    overallstringForDNS = ""
    overalliotDHCPAddress = ""
    overallmDNSEntries = ""

    with Live(table, auto_refresh=False) as liveTable:
        while True:
            time.sleep(0.3)  # arbitrary delay
            # update the renderable internally

            stringForDNS = ""
            dnsEntriesSeen = controller.getDNSEntriesSeen()
            for entries in dnsEntriesSeen:
                stringForDNS = stringForDNS + entries + "\n"

            stringFormDNS = ""
            mdnsEntriesSeen = controller.getmDNSEntriesSeen()
            for entries in mdnsEntriesSeen:
                stringFormDNS = stringFormDNS + entries + "\n"

            iotDHCPAddress = controller.checkforIPAddressAcquisition()
            if iotDHCPAddress == None:
                iotDHCPAddress = ""

            log.debug("StringForDNS: {}".format(stringForDNS))
            log.debug("overallstringForDNS: {}".format(overallstringForDNS))
            log.debug("iotDHCPAddress: {}".format(iotDHCPAddress))
            log.debug("overalliotDHCPAddress: {}".format(overalliotDHCPAddress))
            log.debug("stringFormDNS: {}".format(stringFormDNS))
            log.debug("overallmDNSEntries: {}".format(overallmDNSEntries))

            # Check for updates
            if not ((stringForDNS == overallstringForDNS) & (overalliotDHCPAddress == iotDHCPAddress) & (
                    stringFormDNS == overallmDNSEntries)):
                overallstringForDNS = stringForDNS
                overalliotDHCPAddress = iotDHCPAddress
                overallmDNSEntries = stringFormDNS
                table.add_row(stringForDNS, iotDHCPAddress, stringFormDNS)
                liveTable.update(table, refresh=True)


def dnsStuffRevisited():
    # TABLE
    table = Table(show_lines=True)
    table.add_column("DNS Names Seen")
    table.add_column("IP Addresses Seen")
    table.add_column("mDNS Advertisements")

    # Strings
    overallstringForDNS = ""
    overalliotDHCPAddress = ""
    overallmDNSEntries = ""

    while True:
        stringForDNS = ""
        dnsEntriesSeen = controller.getDNSEntriesSeen()
        for entries in dnsEntriesSeen:
            stringForDNS = stringForDNS + entries + "\n"

        stringFormDNS = ""
        mdnsEntriesSeen = controller.getmDNSEntriesSeen()
        for entries in mdnsEntriesSeen:
            stringFormDNS = stringFormDNS + entries + "\n"

        iotDHCPAddress = controller.checkforIPAddressAcquisition()
        if iotDHCPAddress == None:
            iotDHCPAddress = ""

        # Check for updates
        if not ((stringForDNS == overallstringForDNS) & (overalliotDHCPAddress == iotDHCPAddress) & (
                stringFormDNS == overallmDNSEntries)):
            overallstringForDNS = stringForDNS
            overalliotDHCPAddress = iotDHCPAddress
            overallmDNSEntries = stringFormDNS
            table.add_row(stringForDNS, iotDHCPAddress, stringFormDNS)
            console.print(table)
        time.sleep(3)


def checkForAnIP():
    foundIP = ""
    while not foundIP == "":
        devicesIP = controller.checkforIPAddressAcquisition()
        if devicesIP is not None:
            controller.startNMAP()
            foundIP = devicesIP
        time.sleep(3)


def iotConversations():
    previouslySeenResults = ""
    while True:
        # Table from Rich
        convoTable = Table(title="IOT Conversations")
        convoTable.add_column("Device")
        convoTable.add_column("Protocol")
        convoTable.add_column("Endpoint")
        convoTable.add_column("Port")
        convoTable.add_column("DNS Name")

        theResults = controller.getIOTConversations()
        if theResults is not None:
            if not previouslySeenResults == theResults:
                previouslySeenResults = theResults
                for bothProtocols in theResults:
                    for oneProtocol in bothProtocols:
                        convoTable.add_row(oneProtocol[0], oneProtocol[1], oneProtocol[2], oneProtocol[3],
                                           oneProtocol[4])
                console.print(convoTable)
        time.sleep(3)

def iotCipherSuites():
    previouslySeenResults = ""
    while True:
        # Table from Rich
        convoTable = Table(title="CipherSuites Used")
        convoTable.add_column("Device")
        convoTable.add_column("Endpoint")
        convoTable.add_column("Resolved Name")
        convoTable.add_column("Port")
        convoTable.add_column("Ciphers Offered")

        theResults = controller.getCipherSuitesUsed()
        if theResults is not None:
            if not previouslySeenResults == theResults:
                previouslySeenResults = theResults
                for thisConvo in theResults:
                    device = thisConvo[0]
                    endpoint = thisConvo[1]
                    dnsname = thisConvo[2]
                    port = thisConvo[3]
                    ciphers = '\n'.join(thisConvo[4])
                    convoTable.add_row(device, endpoint, dnsname, port, ciphers)
                console.print(convoTable)
        time.sleep(3)


def nmapResults():
    previouslySeenResults = ""
    while True:
        # Table from Rich
        nmapTable = Table(title="NMAP Results")
        nmapTable.add_column("Port")
        nmapTable.add_column("State")
        nmapTable.add_column("Service")
        nmapTable.add_column("Service Name")

        theResults = controller.getNMAPResults()
        if theResults is not None:
            if not previouslySeenResults == theResults:
                previouslySeenResults = theResults
                for port in theResults:
                    nmapTable.add_row(port[0], port[1], port[2], port[3])
                    # Check if the last index is blank, if it is don't add it to the table
                    # if len(port) == 4:
                    # nmapTable.add_row(port[0], port[1], port[2], port[3])
                    # if len(port) == 3:
                    # nmapTable.add_row(port[0], port[1], port[2], " ")
                console.print(nmapTable)
        time.sleep(10)


####################################
# Kick off MiTM Proxy Default Mode
####################################
def mitmProxyDefaultMode():
    console.print("Press 'd' to begin a Mitmproxy default session")
    while True:
        if keyboard.read_key() == "d":
            controller.startMITMProxyDefaultMode()
            controller.getMiTMProxyHTTPSConvos()


def mitmProxyCloneMode():
    console.print("Press 'c' to begin a Mitmproxy Clone session")
    while True:
        if keyboard.read_key() == "c":
            controller.startMITMProxyCloneMode()
            controller.getMiTMProxyHTTPSConvos()


def mitmProxyLetsEncryptCloneMode():
    console.print("Press 'l' to begin a Mitmproxy LetsEncypt Clone session")
    while True:
        if keyboard.read_key() == "l":
            controller.startMITMProxyLetsEncryptCloneMode()
            controller.getMiTMProxyHTTPSConvos()


def stopMiTMProxy():
    console.print("Press 'e' to end the MiTMproxy task")
    while True:
        if keyboard.read_key() == "e":
            controller.killMitmProxyProcess()


def endItAll():
    console.print("Press 'q' to finish close")
    while True:
        if keyboard.read_key() == "q":
            controller.endGracefully()
            quit()


######################################################################
# Console App
######################################################################
def runConsoleApp():
    # Check for an IP address
    threading.Thread(target=checkForAnIP, args=(), daemon=True).start()
    # DNS tables
    threading.Thread(target=dnsStuffRevisited, args=(), daemon=True).start()
    # Nmap results
    threading.Thread(target=nmapResults, args=(), daemon=True).start()
    # IOT Conversations
    threading.Thread(target=iotConversations, args=(), daemon=True).start()
    # Client Cipher Suites
    threading.Thread(target=iotCipherSuites, args=(), daemon=True).start()
    # MiTMProxy Clone Mode
    threading.Thread(target=mitmProxyCloneMode, args=(), daemon=True).start()
    # MiTMProxy LetsEncrypt Clone Mode
    threading.Thread(target=mitmProxyLetsEncryptCloneMode, args=(), daemon=True).start()
    # MiTMProxy Default Mode
    threading.Thread(target=mitmProxyDefaultMode, args=(), daemon=True).start()
    # MiTMProxy Stop
    threading.Thread(target=stopMiTMProxy, args=(), daemon=True).start()
    # End it all
    threading.Thread(target=endItAll, args=(), daemon=True).start()