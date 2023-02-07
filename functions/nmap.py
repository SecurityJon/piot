#############################################################################
#  This script will nmap the IOT device
#############################################################################

import subprocess
import time

def kickOffNMAP(deviceIP, tempfilepath):
  with open(tempfilepath, "w") as outfile:
    proc1 = subprocess.Popen(['nmap -sT -n -p- -Pn -A --open {}'.format(deviceIP)], shell=True, stdout=outfile, stderr=outfile)
    
  #Check the output of the results, if nmap is telling us that no hosts are up (something went wrong) then run this function again
  #We are going to keep polling this file until we found NMAP is done
  itsFinished = False
  while itsFinished == False:
    with open(tempfilepath) as theFile:
      readInTheFile = theFile.readlines()
      for thisLine in readInTheFile:
        thisLineLower = thisLine.lower()
        if "nmap done:" in thisLineLower:
          if "(0 hosts up)" in thisLineLower:
            # Nmap couldn't scan the device properly, kick off a scan again
            kickOffNMAP(deviceIP, tempfilepath)
          else:
            # Scan completed without issues
            itsFinished = True
    #Sleep for 3 seconds before trying to read the output file again
    time.sleep(3)
  return proc1

#Get HTTPS Convos that are in the MiTM log, this is blocking
# RETURNS: 2 dim list, of ports and their details
def getNMAPresults(tempfilepath):
  results = []
  with open(tempfilepath) as theFile:
    readInTheFile = theFile.readlines()
  for thisLine in readInTheFile:
    thisLineLower = thisLine.lower()
    if "open" in thisLineLower:
      thisLineStripped = thisLine.strip()
      lineArrayBits = thisLineStripped.split()
      #Put each separate section of the result into it's own array, the last set of string needs to go in a single array
      combinedLineArray = []
      lastbitSmushed = ""
      for lineArrayBitCount in range(len(lineArrayBits)):
        if lineArrayBitCount == 0:
          combinedLineArray.append(lineArrayBits[lineArrayBitCount])
        elif lineArrayBitCount == 1:
          combinedLineArray.append(lineArrayBits[lineArrayBitCount])
        elif lineArrayBitCount == 2:
          combinedLineArray.append(lineArrayBits[lineArrayBitCount])
        else:
          lastbitSmushed = lastbitSmushed + lineArrayBits[lineArrayBitCount] + " "
      lastbitSmushedAndStripped = lastbitSmushed.strip()
      combinedLineArray.append(lastbitSmushedAndStripped + " ")
      results.append(combinedLineArray)
  return results