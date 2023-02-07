#############################################################################
#  This script is full of general functionsfolder
#   uses psutil (separate python package)
#############################################################################

import subprocess
import psutil
import os
from pathlib import Path
import config
import logging
import config as config
from mac_vendor_lookup import MacLookup, BaseMacLookup


######################################
#  Logging
######################################
log = logging.getLogger("rich")


# Get the IOT interface, ignoring the routed interface we already have
def getWirelessInterfaceName(routedInterfaceToIgnore):
  wirelessInterfaceWeWant = ""

  proc1 = subprocess.run(['iw dev'], stdout=subprocess.PIPE, shell=True)
  proc2 = subprocess.run(['grep Interface'], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['cut -d \' \' -f2'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
  #Array of interfaces
  wirelessinterfacenames = proc3.stdout.decode().strip().split('\n')

  #Loop through the interfaces looking for one unused
  for theInterface in wirelessinterfacenames:
    #If this interface is our existing routed interface, ignore it
    if not theInterface == routedInterfaceToIgnore:
      if not theInterface == "":
        wirelessInterfaceWeWant = theInterface
        break

  #If the wireless interface we want is empty, then we can't find a free wireless interface that isn't routed already
  if wirelessInterfaceWeWant == "":
      print("Cannot find Wireless Card, exiting")
      quit()

  return wirelessInterfaceWeWant


# Grabs the name of the interface with an IP associated with it (that should be internet connected)
def getRoutedInterfaceName():
  proc1 = subprocess.run(['ip -br addr show'], stdout=subprocess.PIPE, shell=True)
  proc2 = subprocess.run(['tr -s \' \' '], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  interfaceList = proc2.stdout.decode().strip().splitlines()
  routedInterface = ""
  
  #Look through each interface list looking for one that's UP and is not localhost
  #We also want to remove the Pi interface from here and use the secondary one
  for interface in interfaceList:
    interfaceSplit = interface.split()
    if len(interfaceSplit) > 2:
        if interfaceSplit[1] == "UP":
            # We have to check any addresses are not:
            # localhost
            # IPV6 self-ranges
            # self-allocated IPV4 ranges
            if "127.0.0.1" not in interfaceSplit[2] and ":" not in interfaceSplit[2] and "169.254" not in interfaceSplit[2]:
                #Check if this interface is provided by Raspberry Pi, we want to use it, not the other wireless card
                proc3 = subprocess.run(['ip -br link show {}'.format(interfaceSplit[0])], stdout=subprocess.PIPE, shell=True)
                proc4 = subprocess.run(['tr -s \' \' '], input=proc3.stdout, stdout=subprocess.PIPE, shell=True)
                macAddressList = proc4.stdout.decode().strip().split()
                macAddress = macAddressList[2]

                #Pi Mac Addresses start with "b8:27:eb" so make sure it's using that
                if "b8:27:eb" in macAddress:
                  routedInterface = interfaceSplit[0]
                  break
                else:
                  routedInterface = interfaceSplit[0]

  # If we can't find a routed interface
  if routedInterface == "":
    print("Error: Cannot find a routed interface, quitting")
    quit()

  return routedInterface

#HostAPD requires two MAC addresses for two interfaces, so to create the second interface it needs the host adaptor MAC
#to have a spare octet at the end for it to claim. To ensure we have this, we set the MAC of the interface to 00, so there are some to claim
def changeMacAddress(wirelessInterfaceName):
  proc1 = subprocess.run(['ip link show {}'.format(wirelessInterfaceName)], stdout=subprocess.PIPE, shell=True)
  proc2 = subprocess.run(['grep ether'], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['sed \'s/^[[:space:]]*//g\''], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
  proc4 = subprocess.run(['cut -d " " -f2'], input=proc3.stdout, stdout=subprocess.PIPE, shell=True)
  originalWirelessinterfaceMACAddress = proc4.stdout.decode().strip()

  #Split the MAC address
  wirelessinterfaceMACAddressSplit = originalWirelessinterfaceMACAddress.split(":")
  #Set the last octect to be 00
  wirelessinterfaceMACAddressSplit[-1] = "00"  # Set the last element to 00
  #Create the full Mac again
  newWirelessinterfaceMACAddress = ":".join(wirelessinterfaceMACAddressSplit)

  #Change the MAC address
  proc1 = subprocess.run(['ip link set dev {} down'.format(wirelessInterfaceName)], stdout=subprocess.PIPE, shell=True)
  proc5 = subprocess.run(['macchanger --mac {} {}'.format(newWirelessinterfaceMACAddress, wirelessInterfaceName)], stdout=subprocess.PIPE, shell=True)
  proc1 = subprocess.run(['ip link set dev {} up'.format(wirelessInterfaceName)], stdout=subprocess.PIPE, shell=True)

  log.debug("MAC Address of {} changed from {} to {}".format(wirelessInterfaceName, originalWirelessinterfaceMACAddress, newWirelessinterfaceMACAddress))

def getIOTDHCPAddress(dhcpdLeaseFilePath):
  iotDHCPAddress = ""
  with open(dhcpdLeaseFilePath) as theFile:
    readInTheFile = theFile.readlines()
  for thisLine in readInTheFile:
    #Convert to lowercase
    thisLineLower = thisLine.lower()
    if "{" in thisLineLower:
      if "lease" in thisLineLower:
        #Confirm its the right scope
        if "192.168.0." in thisLineLower:
          dhcpAddressSplit = thisLineLower.split()
          iotDHCPAddressWithQuotes = dhcpAddressSplit[1]
          iotDHCPAddress = str(iotDHCPAddressWithQuotes.strip('"'))

  if iotDHCPAddress == "":
    return None
  else:
    return iotDHCPAddress

#This function gets the IP Address/MAC Address/Mac OUI Look up and returns an array, returns None if nothing is in there
def getIOTDHCPAddressFullDetails(dhcpdLeaseFilePath):
  iotDHCPAddress = ""
  IOTDHCPAddressFullDetailsList = []
  with open(dhcpdLeaseFilePath) as theFile:
    readInTheFile = theFile.readlines()
  for thisLine in readInTheFile:
    #Convert to lowercase
    thisLineLower = thisLine.lower()
    if "{" in thisLineLower:
      if "lease" in thisLineLower:
        #Confirm its the right scope
        if "192.168.0." in thisLineLower:
          #Grab the IP Address
          dhcpAddressSplit = thisLineLower.split()
          iotDHCPAddressWithQuotes = dhcpAddressSplit[1]
          iotDHCPAddress = str(iotDHCPAddressWithQuotes.strip('"'))

          #We are going to do a dirty hack now. We're going to read in the file again, parse it until we
          #get to where we are (inside a DHCP lease) and then parse for the other data we want
          with open(dhcpdLeaseFilePath) as theSecondFile:
            thisSecondLineLower = "something we will never see so never hit"
            #Compare the file from the first file to this line. If we're on the same page, contine. Otherwise break out
            while not thisSecondLineLower == thisLineLower:
              thisSecondLine = theSecondFile.readline()
              # Convert to lowercase
              thisSecondLineLower = thisSecondLine.lower()

            #We are now within the DHCP allocated details
            #Loop until we fine a line that contains the MAC address of the device
            while "hardware ethernet" not in thisSecondLine:
              thisSecondLine = theSecondFile.readline()
            #We now have the line with the MAC - split it up and get it out
            macAddressSplit = thisSecondLine.split()
            macAddressWithEndComma = macAddressSplit[2]
            macAddress = str(macAddressWithEndComma.strip(';'))

            #Create temp location if it doesn't exist
            tempDirectory = config.getTempStorageDirectory()
            tempMacLookUpDirectory = makeTemporaryDirectories(tempDirectory, "pwnpidir")
            #Path to download a MAC Address OUI List into. We fix this so we can check later
            BaseMacLookup.cache_path = tempMacLookUpDirectory + 'mac-vendors-list.txt'
            #Define the Mac library to use later
            mac = MacLookup()
            # Check if the above file already exists, if not, download it
            if not os.path.exists(BaseMacLookup.cache_path):
              log.debug("MAC Address OUI list is not downloaded, downloading to {}".format(BaseMacLookup.cache_path))
              mac.update_vendors()  # <- This can take a few seconds for the download and it will be stored in the new path

            #We now have the MAC Address and the OUI list, we can look up the Vendor
            vendorForDevice = ""
            #Try to look up the vendor Mac and if we can't, set an exception
            try:
              vendorForDevice = mac.lookup(macAddress)
            except Exception:
              vendorForDevice = "Unknown"

            #Add everything to the list
            IOTDHCPAddressFullDetailsList.append(iotDHCPAddress)
            IOTDHCPAddressFullDetailsList.append(macAddress)
            IOTDHCPAddressFullDetailsList.append(vendorForDevice)

  if iotDHCPAddress == "":
    return None
  else:
    return IOTDHCPAddressFullDetailsList

def killProcess(processHandle):
    process = psutil.Process(processHandle.pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()
    
    
def killLegacyProcess(processName):
  proc1 = subprocess.run(['ps -ef '], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc2 = subprocess.run(['grep {}'.format(processName)], input=proc1.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
  proc3 = subprocess.run(['grep -v grep'], input=proc2.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
  proc4 = subprocess.run(['awk \'{print $2}\''], input=proc3.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
  processHandles = proc4.stdout.decode().strip()
  processHandlesSplit = processHandles.splitlines()
  
  for eachProcessHandle in processHandlesSplit:  
    log.debug("Killing Process {} on handle {}".format(processName, eachProcessHandle))
    proc5 = subprocess.run(['kill -9 {}'.format(eachProcessHandle)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)

    
def unblockWiFi():
  proc1 = subprocess.run(['rfkill unblock all'], stdout=subprocess.PIPE, shell=True)
  
def restartWirelessInterface(wirelessinterfacename):
  proc1 = subprocess.run(['ip addr flush dev {} '.format(wirelessinterfacename)], stdout=subprocess.PIPE, shell=True)    
  proc2 = subprocess.run(['ip link set dev {} down'.format(wirelessinterfacename)], stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['iw {} set type managed'.format(wirelessinterfacename)], stdout=subprocess.PIPE, shell=True)
  proc4 = subprocess.run(['ip link set dev {} up'.format(wirelessinterfacename)], stdout=subprocess.PIPE, shell=True)
  
  #Confirm the Wifi came up otherwise kill
  proc1 = subprocess.run(['ip link show {}'.format(wirelessinterfacename)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc2 = subprocess.run(['head -n1'], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['cut -d \' \' -f9'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)

  interfaceStatus = proc3.stdout.decode().strip()

  
def makeTemporaryDirectories(parentDirectory, childDirectory):
  fullpath = os.path.join(parentDirectory, childDirectory)
  try: 
    os.mkdir(fullpath)
  # TODO: This probably won't work on Windows......
  except:
    DoNothingAtAllWhyPythonWhy = ""
  fullpath = fullpath + "/"
  return fullpath

def makeTemporaryFiles(filePath):
  try:
    f = open(filePath, "w")
    f.close()      
    #Path(filePath).touch()
  # TODO: This probably won't work on Windows......
  except:
    DoNothingAtAllWhyPythonWhy = ""
  return filePath
    

#Function to determine if a IP address belongs to the Internet or a local network
def isLANAddress(ipAddress):
  #Divide the IP into octets
  ipAddressSplit = ipAddress.split(".")

  #192.168 networks
  if "192" in ipAddressSplit[0]:
    if "168" in ipAddressSplit[1]:
      return True

  #172.16 > 172.31 networks
  if "172" in ipAddressSplit[0]:
    secondPart = int(ipAddressSplit[1])
    if (secondPart > 15) and (secondPart < 32):
      return True

  #10.* networks
  firstPart = int(ipAddressSplit[0])
  if firstPart == 10:
    return True

  #If its not one of the above, must be a cloud address
  return False

#Check if NetworkManager is running. Returns a list of items if it is
def isNetworkManagerRunning():
  proc1 = subprocess.run(['ps -ef'], stdout=subprocess.PIPE, shell=True)
  proc2 = subprocess.run(['grep NetworkManager'], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['grep -v color'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
  listOfOutput = proc3.stdout.decode().strip().split("\n")

  # Remove blank lines
  new_list = []
  for x in listOfOutput:
    if x != '':
      new_list.append(x)
  return new_list

#If Network Manager was running, attempt to kill it.
#Returns true if it was running, false if it wasn't
def wasNetworkManagerRunningKillItIfSo():
  networkManagerList = isNetworkManagerRunning()
  if (len(networkManagerList) > 0):
    log.debug("NetworkManager is currently running")
    while (len(networkManagerList) > 0):
      proc1 = subprocess.run(['systemctl stop NetworkManager'], stdout=subprocess.PIPE, shell=True)
      networkManagerList = isNetworkManagerRunning()
    #Return true, it was running
    return True
    log.debug("NetworkManager has now been stopped")
  else:
    #Network Manager was not running
    log.debug("NetworkManager was not running")
    return False

#Start the NetworkManager process
def startNetworkManager():
  proc1 = subprocess.run(['systemctl start NetworkManager'], stdout=subprocess.PIPE, shell=True)
