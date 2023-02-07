#############################################################################
#   This script creates a Wireless Access Point with DHCP and DNS
#
#   Uses sudo apt install hostapd isc-dhcp-server
#############################################################################

#Import our other scripts for their methods
import functions.wifi_pairing_scanning as wifi
import functions.tshark_listening as tshark
import subprocess
import time
import config
import logging


######################################
#  Logging
######################################
log = logging.getLogger("rich")
  

def createDHCPLeaseFileForIOT(dhcpdConfigFile):
    configFileContents = '''
subnet 192.168.0.0 netmask 255.255.255.248 {  
range 192.168.0.2 192.168.0.6;    
option broadcast-address 192.168.0.7;    
option routers 192.168.0.1;    
option domain-name \"local\";    
option domain-name-servers 8.8.8.8, 8.8.4.4;
}
subnet 192.168.1.0 netmask 255.255.255.248 {  
range 192.168.1.2 192.168.1.6;    
option broadcast-address 192.168.1.7;    
option routers 192.168.1.1;    
option domain-name \"local\";    
option domain-name-servers 8.8.8.8, 8.8.4.4;
}
'''
    with open(dhcpdConfigFile, 'w') as f: 
        f.write(configFileContents)

  
    
def createHostAPDFileForIOT(wirelessInterfaceName, hostAPDConfigFile, wirelessAccessPointSSIDForIOT, wirelessAccessPointPasswordForIOT, wirelessInterfaceNameForManagement, wirelessAccessPointSSIDForManagement, wirelessAccessPointPasswordForManagement):
    configFileContents = '''
interface={}

#IOT Interface
hw_mode=g
ssid={}
ieee80211d=1
channel=6
country_code=UK
ieee80211n=1
auth_algs=1
wpa=2
wpa_passphrase={}
wpa_key_mgmt=WPA-PSK
#bssid=DE:AD:BE:EF:00:01

#Management Interface
bss={}
hw_mode=g
ssid={}
ieee80211d=1
channel=6
country_code=UK
ieee80211n=1
auth_algs=1
wpa=2
wpa_passphrase={}
wpa_key_mgmt=WPA-PSK
#bssid=DE:AD:BE:EF:00:02
'''.format(wirelessInterfaceName, wirelessAccessPointSSIDForIOT, wirelessAccessPointPasswordForIOT, wirelessInterfaceNameForManagement, wirelessAccessPointSSIDForManagement, wirelessAccessPointPasswordForManagement)
  
    with open(hostAPDConfigFile, 'w') as f:
        f.write(configFileContents)


#Enable IP traffic forwarding
def forwardIPTraffic():
  proc1 = subprocess.run(['sysctl -w net.ipv4.ip_forward=1'], stdout=subprocess.PIPE, shell=True)
  proc2 = subprocess.run(['sysctl --system'], stdout=subprocess.PIPE, shell=True)
  
def bringUpHostAPD(hostAPDConfigFile, debugOutputFile):
  command = 'hostapd {}'.format(hostAPDConfigFile)
  log.debug("HOSTAPD Command: {}".format(command))

  with open(debugOutputFile, "w") as outfile:
    proc1 = subprocess.Popen([command], shell=True, stdout=outfile, stderr=outfile)
  return proc1

def assignIPAddressToIOTAdaptor(wirelessInterfaceName):
  ipAddress = "192.168.0.1"
  proc1 = subprocess.run(['ip addr flush dev {}'.format(wirelessInterfaceName)], stdout=subprocess.PIPE, shell=True)
  proc2 = subprocess.run(['ip addr add {}/29 broadcast 192.168.0.7 dev {}'.format(ipAddress, wirelessInterfaceName)], stdout=subprocess.PIPE, shell=True)
  return ipAddress

def assignIPAddressToManagementAdaptor(wirelessInterfaceName):
  ipAddress = "192.168.1.1"
  proc1 = subprocess.run(['ip addr flush dev {}'.format(wirelessInterfaceName)], stdout=subprocess.PIPE, shell=True)
  proc2 = subprocess.run(['ip addr add {}/29 broadcast 192.168.1.7 dev {}'.format(ipAddress, wirelessInterfaceName)], stdout=subprocess.PIPE, shell=True)
  return ipAddress

def startDHCPD(dhcpdConfigFile, dhcpdleasesfile, wirelessInterfaceName, wirelessInterfaceNameForManagement):
  command = '/usr/sbin/dhcpd -f -cf {} -lf {} {} {}'.format(dhcpdConfigFile, dhcpdleasesfile, wirelessInterfaceName, wirelessInterfaceNameForManagement)
  log.debug("DHCPD Command: {}".format(command))
  proc1 = subprocess.Popen([command], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  return proc1

def createNATRulesForIPTables(wirelessInterfaceName, routedInterfaceName):
    proc1 = subprocess.run(['iptables -t nat -A POSTROUTING -o {} -j MASQUERADE'.format(routedInterfaceName)], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc2 = subprocess.run(['iptables -A FORWARD -i {} -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT '.format(routedInterfaceName, wirelessInterfaceName)], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc3 = subprocess.run(['iptables -A FORWARD -i {} -o {} -j ACCEPT'.format(wirelessInterfaceName, routedInterfaceName)], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc4 = subprocess.run(['iptables -A INPUT -j ACCEPT'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    proc5 = subprocess.run(['iptables -A OUTPUT -j ACCEPT'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    
def deleteNATRulesForIPTables():
  proc1 = subprocess.run(['iptables -t nat -F'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  proc2 = subprocess.run(['iptables -t mangle -F'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  proc3 = subprocess.run(['iptables -F'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
  proc4 = subprocess.run(['iptables -X'], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


#Stop Network Manager if it is running as this can kill the Access Point
def stopNetworkManager():

    proc1 = subprocess.run(['ps - ef'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
    proc2 = subprocess.run(['grep NetworkManager'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
    proc3 = subprocess.run(['grep - v color'], input=proc2.stdout, stdout=subprocess.PIPE, shell=True)
    listOfOutput = proc3.stdout.decode().strip().split("\n")

    proc2 = subprocess.run(['systemctl stop NetworkManager '], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)