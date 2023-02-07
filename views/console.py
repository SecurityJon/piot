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
    while foundIP == "":
        devicesIP = controller.checkforIPAddressAcquisition()
        if devicesIP is not None:
            console.print("Device has been connected!")
            global IOTConnected
            IOTConnected = True
            controller.startNMAP()
            foundIP = devicesIP
        time.sleep(3)


def iotConversations():
    previouslySeenResults = ""
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
    controller.startMITMProxyDefaultMode()
    controller.getMiTMProxyHTTPSConvos()


def mitmProxyCloneMode():
    controller.startMITMProxyCloneMode()
    controller.getMiTMProxyHTTPSConvos()


def mitmProxyLetsEncryptCloneMode():
    controller.startMITMProxyLetsEncryptCloneMode()
    controller.getMiTMProxyHTTPSConvos()


def stopMiTMProxy():
    controller.killMitmProxyProcess()


def endItAll():
    controller.endGracefully()
    quit()


######################################################################
# Console App
######################################################################
def runConsoleApp():
    # Check for an IP address
    threading.Thread(target=checkForAnIP, args=(), daemon=True).start()
    # Menu
    threading.Thread(target=menu, args=(), daemon=True).start()


######################################################################
# Menu System
######################################################################
def menuText():
    console.print("")
    console.print("")
    console.print("#################################################")
    console.print("PIOT Menu")
    console.print("")
    console.print("Press '{}' to view and DNS records seen".format('a'))
    console.print("Press '{}' to view any conversations seen".format('b'))
    console.print("Press '{}' to view cipher suites offered by the device".format('c'))
    console.print("Press '{}' to view results of an NMAP scan".format('d'))
    console.print("Press '{}' to start MiTM Proxy in its default configuration".format('e'))
    console.print("Press '{}' to start MiTM Proxy using cloned Certificate Chains".format('f'))
    console.print("Press '{}' to start MiTM Proxy using LetsEncrypt Certificates".format('g'))
    console.print("Press '{}' to stop MiTM Proxy".format('h'))
    console.print("Press '{}' to exit the programme".format('q'))
    console.print("#################################################")
    console.print("")
    console.print("")



def menu():
    #Call menuText once for the user
    menuText()

    #Loop until programme end
    while True:
        # Block until a keyboard event has been seen
        event = keyboard.read_event()
        # Check if an IOT device has been given an IP yet
        if ('IOTConnected' not in globals()) and (event.event_type == keyboard.KEY_DOWN):
            console.print("IOT device not yet connected, please connect a device")
        else:
            console.print("Performing action, please wait a moment....")
            console.print("")
            if event.event_type == keyboard.KEY_DOWN and event.name == "a":
                dnsStuffRevisited()
            if event.event_type == keyboard.KEY_DOWN and event.name == "b":
                iotConversations()
            if event.event_type == keyboard.KEY_DOWN and event.name == "c":
                iotCipherSuites()
            if event.event_type == keyboard.KEY_DOWN and event.name == "d":
                nmapResults()
            if event.event_type == keyboard.KEY_DOWN and event.name == "e":
                mitmProxyDefaultMode()
            if event.event_type == keyboard.KEY_DOWN and event.name == "f":
                mitmProxyCloneMode()
            if event.event_type == keyboard.KEY_DOWN and event.name == "g":
                mitmProxyLetsEncryptCloneMode()
            if event.event_type == keyboard.KEY_DOWN and event.name == "h":
                stopMiTMProxy()
            if event.event_type == keyboard.KEY_DOWN and event.name == "q":
                endItAll()

            #Call the menu again
            menuText()