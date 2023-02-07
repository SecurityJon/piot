# PIOT - an IOT Testing Tool for the Pi - v0.1

## Introduction
PIOT (Pronouced Pi IOT) is a IOT security testing tool designed to highlight security flaws in a black box environment for IOT (or any device) way. The tool is designed to permit security testers to run basic tests and gain information about an IOT device quickly and easily without having to set up complex Man In The Middle environments.

PIOT is designed to be set up and ran from a Raspberry Pi (although it will run on Linux too) for a quick method to perform IOT testing. It is recommended that it is set up on a Pi you aren't using for anything else, then it can be simply powered on, perform testing and power it off and put it in a drawer again. 

Once installed and running, PIOT presents itself as a Wi-Fi access point that an IOT device should be connected to. From here the terminal or web interface can be used to gather information or run basic tests.

PIOT offers the following functionality:

 - Automated NMAP port scanning of the IOT device
 - A list of all DNS queries made by the IOT device
 - A list of all mDNS queries made by the IOT device
 - A list of any Server Name Indication (SNI) captured from the IOT device
 - A list of usable TLS Cipher Suites offered by the IOT device for each endpoint it communicates with
   - This is useful if attempting a Man In The Middle attack or reviewing security best practice
 - A list of network communications (endpoint and port) that the IOT device has communicated with
 - A PCAP dump of all network communications the IOT device has had, for offline analysis
 - Attacks
   - A Man In The Middle attack using MITMProxy in its default configuration to look for TLS misconfigurations
   - A Man In The Middle attack using MITMProxy which clones the entire certificate chain for each endpoint the IOT device has communicated with
   - A Man In The Middle attack using MITMProxy which uses LetsEncrypt to create a certificate (based on a subdomain supplied) for each endpoint the IOT device has communicated with

## Attacks

IOT devices nearly always employ communication with an internet endpoint for communication and usage. This permits the device to be controlled by a mobile application remotely, and integrate with additional services such as Amazon Alexa.

In most cases, this communication is encrypted, which makes understanding network traffic flows between the IOT device and the internet endpoint extremely difficult without opening the IOT device up.

PIOT aids by offering three methods to potentially perform a Man In The Middle attack against the IOT device

   - 'Basic MiTM Attack' - Using MITMProxy in its default configuration
     - Devices which are not validating TLS certificates against any criteria may be vulnerable to this. 
     - This can be enabled at any time and any further TLS communication will be subject to the MiTM attack
     - See 'THE DEFAULT ATTACK - "IT JUST WORKS"' attack here: https://bishopfox.com/blog/breaking-https-in-the-iot
   - 'Advanced MiTM Attack' - Using MITMProxy which clones the entire certificate chain for each endpoint the IOT device has communicated with
     - PIOT 'walks' the TLS certificate chain of each DNS endpoint that the IOT device has communicated with. For each endpoint, the TLS certificate is cloned, both the endpoint certificate (leaf node) and the top level certificate (root node) 
     - This must be enabled after the IOT device has be used and has communicated with each internet endpoint you wish to Man In The Middle, otherwise PIOT does not have a TLS chain to clone. This cannot be performed 'on the fly' due to the length of time it take to clone a certificate chain, and time outs from the IOT device
     - See 'THE LOOK-ALIKE CA ATTACK - "CLONING THE ROOT OF TRUST"' attack here: https://bishopfox.com/blog/breaking-https-in-the-iot
   - 'Expert MiTM Attack' - Using MITMProxy and LetsEncrypt to create a certificate (based on a subdomain supplied) for each endpoint the IOT device has communicated with
     - PIOT creates a legit certificate prefixed by the name of each DNS endpoint that the IOT device has communicated with. For example, the endpoint 'alexa.com' would have a certificate created for 'alex.com.domainyouown.com' 
     - This is performed using LetsEncrypt and Amazon AWS Route53, configuration of this must be done prior to using PIOT and configured in the config file. 
     - This attack must be enabled after the IOT device has be used and has communicated with each internet endpoint you wish to Man In The Middle, otherwise PIOT does not have a TLS certificate to clone. This cannot be performed 'on the fly' due to the length of time it take to create a certificate, and time outs from the IOT device
     - See 'THE INCORRECT NAME ATTACK - “THE OL’ SWITCHEROO”' attack here: https://bishopfox.com/blog/breaking-https-in-the-iot

For each attack, the IOT device is briefly disconnected from PIOT to force a reset of it's network communication. It is likely that the IOT device will stop responding to commands after this, as its encrypted communication is now being Man In The Middle'd and it is not succeptable to this. Stop the attack to resume control of the IOT device and try another attack.  

## Installation

### For Development 
The following build environments have been tested:
 - PyCharm-Community under Python 3.6 on Ubuntu (x86)
 - PyCharm-Community under Python 3.10 on Kali (arm64)

Install the following external dependencies
`sudo apt-get install hostapd dhcpd isc-dhcp-server python3 python3-pip tshark iptables nmap openssl`

Install all python requirements in PyCharm listed in `pythonrequirements.txt`

### In Production

#### On Linux

Install the following external dependencies
`sudo apt-get install hostapd dhcpd isc-dhcp-server python3 python3-pip tshark iptables nmap openssl`

Install all python requirements in PyCharm listed in `pythonrequirements.txt`

#### On Raspberry Pi

PIOT has been tested with the following configuration:

 - Raspberry Pi 3B+
 - Rasberry Pi OS Bullseye
 - Python 3.10.9


##### Get Pip
```
sudo curl -sS https://bootstrap.pypa.io/get-pip.py | python3
```

##### Force cryptography to be install via piwheels so that mitmproxy will build
```
sudo pip3 install cryptography -i https://www.piwheels.org/simple
```

##### Force numpy to be installed as it breaks when getting from pip
```
sudo pip3 install numpy -i https://www.piwheels.org/simple
```

##### Force psutil install as it doesn't like pip
```
sudo pip3 install psutil -i https://www.piwheels.org/simple
```

##### Install the other packages we need
```
sudo apt-get install hostapd dhcpd isc-dhcp-server tshark iptables rustc iw rfkill kbd macchanger
```

##### Install requirements
```
sudo pip3 install -r pythonrequirements.txt
```

##### Install the last parts to get numpy working, we need to add a previous repo
```
sudo touch /etc/apt/sources.list.d/buster_for_piot.list
echo 'deb http://deb.debian.org/debian/ buster main' | sudo tee -a /etc/apt/sources.list.d/buster_for_piot.list
echo 'deb http://deb.debian.org/debian/ buster-updates main' | sudo tee -a /etc/apt/sources.list.d/buster_for_piot.list
sudo apt update
sudo apt-get install libatlas-base-dev
```

### Required Configuration
For the 'Expert MiTM Attack', PIOT uses Amazon AWS Route53 and LetsEncrypt to create legitimate certificates. This requires the purchase of a domain and setting up an Amazon AWS account to host it on. Access keys for this account should be created and then added to the following fields in `config.txt`  

 - ` AWS_Access_key_ID = ` - The AWS Access Key of the Account should be added here 
 - `AWS_Secret_access_key = ` - The AWS Secret Key of the Account should be added here
 - `letscrypt_email_address = ` - LetsEncrypt requires an email address to be added for created certificates for alerts. Enter your email address in here
 - `route53_owned_domain = ` - A domain controlled by Amazon AWS Route53, this should take the form of the domain you wish to use, like 'piot.com' 

## Usage

PIOT currently requires a Wireless Dongle that can be placed into Manage/Access Point mode, as well as a separate, existing internet connection. It has been tested with tested with a `Panda PAU06 wireless dongle`

To start PIOT run `sudo python3 main.py`. The tool will launch two Wireless SSIDs:

 - `PwnPi_For_IOT` - The IOT device should be connected to this. 
 - `PwnPi_For_Management` - This should be connected to for interacting with PIOT

For IOT devices that must be set up using the same SSID as the mobile device is connected to, first pair the mobile device with PIOT using the `PwnPi_For_IOT` SSID and then go through the set up proceedure. After this is done, disconnect the mobile device from PIOT and delete the `PwnPi_For_IOT` SSID from the mobile device's Prefered Network List. Now restart PIOT and connect the mobile device to the `PwnPi_For_Management` SSID. This will ensure that all Mobile Application to IOT device communication goes through the internet connection and the only traffic seen coming through PIOT is that of the IOT device. 

## TroubleShooting

If everything is working correctly, the output should contain 'pIOT is now up and running!'. If PIOT does not bring up two Wireless Networks, or cannot connect an IOT device, try the following. 

In the config file, make the following changes
```
consoleApp = True
MAINLOGGINGLEVEL = "DEBUG"
```
Run the application manually with `sudo python3 main.py` to see console output. More than likely a dependency hasn't be installed correctly or there is an issue with the type of Wireless Dongle used. 

On occation if PIOT has been restarted several times, hostAPD fails to bring up the Wireless Interfaces, the easiest way to resolve this is to restart the Operating System and try again. If this still doesn't work, try changing Wireless adaptor. HostAPD can be really difficult to find an adaptor to work with.   

Once running, after a short time PIOT will create two new Wireless Networks, one to connect the IOT device to, and one to connect a mobile device or laptop into to control PIOT and view information. 
If the IOT device needs to be connected to a specific Wireless network, the IOT Wireless endpoint can be configured in the config file under these options
```
wirelessAccessPointSSIDForIOT = 
wirelessAccessPointPasswordForIOT =
```
 