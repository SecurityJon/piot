#############################################################################
#	This script scans for new Wireless Access Points
#	It is used for finding IOT devices that use Wifi to set up
#	First it scans th environment for Wifi, then you put the IOT in pairing 
#	mode and it scans the environment again to see whats around
#############################################################################

#import command 
import subprocess
import time

def scanAccessPoints(wirelessInterfaceName, timesToScan, sleepTime):
  combinedScanResultsList = []
  for loopy in timesToScan:
    proc1 = subprocess.run(['iw dev {} scan'.format(wirelessInterfaceName)], stdout=subprocess.PIPE, shell=True)
    proc2 = subprocess.run(['grep SSID:'], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
    proc3 = subprocess.run(['cut -d \' \' -f2'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
    proc4 = subprocess.run(['grep -v -e \'^[[:space:]]*$\''], input=proc3.stdout, stdout=subprocess.PIPE, shell=True)
    proc5 = subprocess.run(['sort'], input=proc4.stdout, stdout=subprocess.PIPE, shell=True)
    proc6 = subprocess.run(['uniq'], input=proc5.stdout, stdout=subprocess.PIPE, shell=True)
  
    scanResult = proc6.stdout.decode()
    scanResultList = scanResult.split("\n")

    # Add this list of Wifi access points to the one we've already created
    combinedScanResultsList.extend(scanResultList)
    #print(combinedScanResultsList)
    time.sleep(sleepTime)  
  
  #Remove all duplicates from the scan result list
  combinedScanResultsSet = set()
  for x in combinedScanResultsList:
    combinedScanResultsSet.add(x)
  
  return combinedScanResultsSet
  

# Scan for access points
timesToScan = range(7)
sleepTime = 2


#wirelessinterfacename = getWirelessInterfaceName()
#print("Unblocking Wireles Interface")
#unblockWiFi()
#print("Restarting Wireless Interface")
#restartWirelessInterface(wirelessinterfacename)
#print("Scanning the Environment")
#initalAccessPoints = scanAccessPoints(wirelessinterfacename, timesToScan, sleepTime)

#TODO: Check here if we have an empty/single? set size, because the wifi card has probably naffed itself and we need to reset it if so

#input("Put the IOT device into pairing mode now, press ENTER when done")
#print("Scanning for IOT device")
#secondStageAccessPoints = scanAccessPoints(wirelessinterfacename, timesToScan, sleepTime)

#TODO: We might have multiple Acces Points detected here, get the user to select which one is likely the IOT to emulate
        
#print(secondStageAccessPoints.difference(initalAccessPoints))
