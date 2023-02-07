#############################################################################
#	This script listens on the WiFi MiTM network we have set up
#	and spits out information on specific IOT protocols it sees
#############################################################################

#import asyncio
import subprocess
import time
import string
import functions.functions as functions

def kickOffTShark(wirelessinterfacename, tempfilepath):  
  #proc1 = subprocess.Popen(['tshark -i {} -w {}'.format(wirelessinterfacename, tempfilepath)], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  proc1 = subprocess.Popen(['tshark -i {} -w {}'.format(wirelessinterfacename, tempfilepath)], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  
  return proc1

#DNS queries, returns a unique list of DNS names, not mDNS, only over port 53
def dnsQueries(tempfilepath):
  proc1 = subprocess.run(['tshark -r {} -Y "dns && (udp.dstport == 53 || tcp.dstport == 53)" -n -T fields -e dns.qry.name -e dns.a'.format(tempfilepath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc2 = subprocess.run(['grep -v -e \'^[[:space:]]*$\''], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['awk -F \'\t\' \'$1 != null\''], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
  proc4 = subprocess.run(['sort'], input=proc3.stdout, stdout=subprocess.PIPE, shell=True)
  proc5 = subprocess.run(['uniq'], input=proc4.stdout, stdout=subprocess.PIPE, shell=True)
  listOfOutput = proc5.stdout.decode().strip().split("\n")
  listFromStripping = []
  for iterator in listOfOutput:
    listFromStripping.append(iterator.strip())
  tempSet = set(listFromStripping)
  return list(tempSet)

def getDHCPAddress(tempfilepath):
  proc1 = subprocess.run(['tshark -r {} -Y "bootp.option.dhcp == 5" -T fields -e bootp.ip.your'.format(tempfilepath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc2 = subprocess.run(['sort'], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['uniq'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
  return proc3.stdout.decode().strip()

def getDNSAddressFromIP(tempfilepath, ipAddress):
  proc1 = subprocess.run(['tshark -r {} -Y "dns.a == {}" -T fields -e dns.qry.name'.format(tempfilepath, ipAddress)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc2 = subprocess.run(['sort'], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['uniq'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
  return proc3.stdout.decode().strip()

#mDNS queries, returns a unique list of mDNS names
def getmDNSAdvertisements(tempfilepath):
  proc1 = subprocess.run(['tshark -r {}  -n -T fields -e dns.resp.name -Y "udp.port == 5353"'.format(tempfilepath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc2 = subprocess.run(['grep -v -e \'^[[:space:]]*$\''], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['sort'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
  proc4 = subprocess.run(['uniq'], input=proc3.stdout, stdout=subprocess.PIPE, shell=True)  
  listOfOutput = proc4.stdout.decode().strip().split("\n")
  listFromStripping = []
  for iterator in listOfOutput:
    iteratorSplitOnceAgainByCommaThisTime = iterator.split(",")
    for hopefullyLastIterator in iteratorSplitOnceAgainByCommaThisTime:
      listFromStripping.append(hopefullyLastIterator.strip())
  tempSet = set(listFromStripping)
  return list(tempSet)

#Returns a list of TCP/UDP conversations between an endpoint and the cloud
#We only focus on the Cloud side her for ports, we don't care about ephemeral ports on the client
#Returns a two dim list of unique convos, ports, dns entries and protocols
#[
#   [IOTAddress, "tcp", CloudAddress, NetworkPort, DNS_Of_Cloud_Address],
#   [IOTAddress, "tcp", CloudAddress, NetworkPort, DNS_Of_Cloud_Address],
#   [IOTAddress, "udp", CloudAddress, NetworkPort, DNS_Of_Cloud_Address],
#   [IOTAddress, "udp", CloudAddress, NetworkPort, DNS_Of_Cloud_Address]
#]
def getConversations(tempfilepath, dhcpaddress):
  #List to hold Cloudendpoints with ports, protocols and dns that we'll uniq later on
  allCloudEndpointsAndPortsAndProtocol = []
  tcpCloudEndPointsAndPorts = []
  udpCloudEndPointsAndPorts = []
  tempCloudEndPointsAndPortsAndStuff = []

  ########################
  # TCP
  ########################
  tempCloudEndPointsAndPortsAndStuff = []
  proc1 = subprocess.run(['tshark -r {} -n -q -z conv,tcp'.format(tempfilepath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc2 = subprocess.run([' tr -s \' \''], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['grep "."'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
  proc4 = subprocess.run(['cut -d \' \' -f1,2,3'], input=proc3.stdout, stdout=subprocess.PIPE, shell=True)

  #Split the convo into lines
  fullConvo = proc4.stdout.decode().strip()
  fullConvoSplitByLine = fullConvo.split("\n")

  #Loop through each line
  for thisConvo in fullConvoSplitByLine:
    #Confirm the line contains our IOT device
    if dhcpaddress in thisConvo:
      # Split the conversation into IOT and Cloud endpoints
      thisConvoSplitByDeviceOrCloud = thisConvo.split('<->')
      if len(thisConvoSplitByDeviceOrCloud) > 1:
        #Split the IOT endpoint into IP and port
        iotIPAndPort = thisConvoSplitByDeviceOrCloud[0].split(':')
        #Check the IP address we have matches the IOT device
        if iotIPAndPort[0] == dhcpaddress:
          cloudEndPointAndPort = thisConvoSplitByDeviceOrCloud[1].strip()
          #Split the Cloud side into IP and port
          cloudEndPointSplitUp = cloudEndPointAndPort.split(":")
          #Check that the Cloud side is Cloud and not another local address (like the router)
          if functions.isLANAddress(cloudEndPointSplitUp[0]) == False:
            tempCloudEndPointsAndPortsAndStuff.append(cloudEndPointAndPort)

  #Unique the Cloud endpoints then put them back in the list
  uniqSetOfCloudEndpoints = set(tempCloudEndPointsAndPortsAndStuff)
  tcpCloudEndPointsAndPorts = list(uniqSetOfCloudEndpoints)


  ########################
  # UDP
  ########################
  tempCloudEndPointsAndPortsAndStuff = []
  proc1 = subprocess.run(['tshark -r {} -n -q -z conv,udp'.format(tempfilepath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc2 = subprocess.run([' tr -s \' \''], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['grep "."'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
  proc4 = subprocess.run(['cut -d \' \' -f1,2,3'], input=proc3.stdout, stdout=subprocess.PIPE, shell=True)

  #Split the convo into lines
  fullConvo = proc4.stdout.decode().strip()
  fullConvoSplitByLine = fullConvo.split("\n")

  #Loop through each line
  for thisConvo in fullConvoSplitByLine:
    #Confirm the line contains our IOT device
    if dhcpaddress in thisConvo:
      # Split the conversation into IOT and Cloud endpoints
      thisConvoSplitByDeviceOrCloud = thisConvo.split('<->')
      if len(thisConvoSplitByDeviceOrCloud) > 1:
        #Split the IOT endpoint into IP and port
        iotIPAndPort = thisConvoSplitByDeviceOrCloud[0].split(':')
        #Check the IP address we have matches the IOT device
        if iotIPAndPort[0] == dhcpaddress:
          cloudEndPointAndPort = thisConvoSplitByDeviceOrCloud[1].strip()
          #Split the Cloud side into IP and port
          cloudEndPointSplitUp = cloudEndPointAndPort.split(":")
          #Check that the Cloud side is Cloud and not another local address (like the router)
          if functions.isLANAddress(cloudEndPointSplitUp[0].strip()) == False:
            tempCloudEndPointsAndPortsAndStuff.append(cloudEndPointAndPort)

  #Unique the Cloud endpoints then put them back in the list
  uniqSetOfCloudEndpoints = set(tempCloudEndPointsAndPortsAndStuff)
  udpCloudEndPointsAndPorts = list(uniqSetOfCloudEndpoints)

  #######################
  # Add DNS
  #######################
  #Finally return a new double list of IOT endpoints and Cloud ones
  tcpListToReturn = []
  udpListToReturn = []

  #TCP First
  for oneCloudEndpointAndPort in tcpCloudEndPointsAndPorts:
    #Split the Cloud endpoint:port into IP and port
    cloudEndpointAndPortSplitUp = oneCloudEndpointAndPort.split(":")
    ipAddressToDNSSearch = cloudEndpointAndPortSplitUp[0]
    portOfThisEntry = cloudEndpointAndPortSplitUp[1]
    # Search the PCAP for the DNS entry that matches the IP address
    theDNSEntry = getDNSAddressFromIP(tempfilepath, ipAddressToDNSSearch)
    #Smash it all together
    tcpListToReturn.append([dhcpaddress, "tcp", ipAddressToDNSSearch, portOfThisEntry, theDNSEntry])

  #UDP Second
  for oneCloudEndpointAndPort in udpCloudEndPointsAndPorts:
    #Split the Cloud endpoint:port into IP and port
    cloudEndpointAndPortSplitUp = oneCloudEndpointAndPort.split(":")
    ipAddressToDNSSearch = cloudEndpointAndPortSplitUp[0]
    portOfThisEntry = cloudEndpointAndPortSplitUp[1]
    # Search the PCAP for the DNS entry that matches the IP address
    theDNSEntry = getDNSAddressFromIP(tempfilepath, ipAddressToDNSSearch)
    #Smash it all together
    udpListToReturn.append([dhcpaddress, "udp", ipAddressToDNSSearch, portOfThisEntry, theDNSEntry])

  #Smash TCP and UDP together
  allCloudEndpointsAndPortsAndProtocol.append(tcpListToReturn)
  allCloudEndpointsAndPortsAndProtocol.append(udpListToReturn)

  return allCloudEndpointsAndPortsAndProtocol

#Returns a list of TLS SNI names that have been requested
def getSNIFromTLS(tempfilepath):
  proc1 = subprocess.run(['tshark -r {} -Tfields -e ssl.handshake.extensions_server_name -Y "ssl.handshake.extension.type == 0"'.format(tempfilepath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc2 = subprocess.run(['grep -v -e \'^[[:space:]]*$\''], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
  proc3 = subprocess.run(['awk -F \'\t\' \'$1 != null\''], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
  proc4 = subprocess.run(['sort'], input=proc3.stdout, stdout=subprocess.PIPE, shell=True)
  proc5 = subprocess.run(['uniq'], input=proc4.stdout, stdout=subprocess.PIPE, shell=True)
  listOfOutput = proc5.stdout.decode().strip().split("\n")
  listFromStripping = []
  for iterator in listOfOutput:
    listFromStripping.append(iterator.strip())
  tempSet = set(listFromStripping)
  return list(tempSet)

#Returns a list of tshark output, each line in a new list item
def getItAllMinusSomeBits(tempfilepath, ouraddress):
  proc1 = subprocess.run(['tshark -r {} -Y "!((ip.src=={}) or (ip.dst=={}) or arp)"'.format(tempfilepath, ouraddress, ouraddress)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
  theoutput = proc1.stdout.decode()
  theoutputSplit = theoutput.split("\n")
  return theoutputSplit


#Returns a list of cipher suites a client (supplied) has permitted to be used in convo with the Cloud
#Can be useful if the client is willing to drop back to a really insecure one and we can MiTM
#Uses the getConversations() method to grab the main convos for processing
def getCipherSuitesPermittedByClient(tempfilepath, ouraddress):

  finalCipherSuiteListForAllConvos = []

  #Use getConversations() to get the convos that have happened
  completeConvos = getConversations(tempfilepath, ouraddress)

  #Loop through each of the convos grabbing the source and dest address
  #  [ [ [IOTAddress, "tcp", CloudAddress, NetworkPort, DNS_Of_Cloud_Address] ], [ [IOTAddress, "udp", CloudAddress, NetworkPort, DNS_Of_Cloud_Address] ] ]
  for convoPerProtocol in completeConvos:
    # Check the convo list isn't empty before we try to use it
    if len(convoPerProtocol) > 0:
      for thisProtocolConvo in convoPerProtocol:
        iotAddress = thisProtocolConvo[0]
        protocol = thisProtocolConvo[1]
        cloudAddress = thisProtocolConvo[2]
        networkport = thisProtocolConvo[3]
        dnsNameForCloudAddress = thisProtocolConvo[4]

        #if this is a TCP convo, we can search for handshakes with it
        if protocol == "tcp":
          proc1 = subprocess.run(['tshark -r {} -Y "ssl.handshake.ciphersuites and ip.src=={} and ip.dst=={} and tcp.dstport == {}" -Vx'.format(tempfilepath, iotAddress, cloudAddress, networkport)],stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True)
          proc2 = subprocess.run(['grep "Cipher Suite:"'], input=proc1.stdout, stdout=subprocess.PIPE, shell=True)
          theoutput = proc2.stdout.decode()
          #List to hold Source/Dest/CipherList
          clientConvoList = []
          #List to hold ciphers
          permittedCipherSuiteList = []

          #Split into multiple lines for processing
          theoutputSplit = theoutput.split("\n")
          for eachLine in theoutputSplit:
            #Check there is something to split
            if not eachLine == "":
              # Split into preamble and ciphersuite
              suiteAndPremableToSplit = eachLine.split(":")
              clientSuite = suiteAndPremableToSplit[1].strip()
              permittedCipherSuiteList.append(clientSuite)

          clientConvoList.append(iotAddress)
          clientConvoList.append(cloudAddress)
          clientConvoList.append(dnsNameForCloudAddress)
          clientConvoList.append(networkport)
          clientConvoList.append(permittedCipherSuiteList)

          finalCipherSuiteListForAllConvos.append(clientConvoList)


  return finalCipherSuiteListForAllConvos

