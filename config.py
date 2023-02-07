#############################################################################
#  This module contains config items
#############################################################################
import logging
import os
def readInConfigFile(paramToGet):
    configfilename = "config.txt"

    #Grab the dev version if it exists, otherwise use the local one
    if (os.path.isfile("dev_extras/" + configfilename) == True):
        configfilename = "dev_extras/" + configfilename

    #Log what we're getting and from where
    logging.DEBUG("Config file {} used to get parameter {}".format(configfilename, paramToGet))

    with open(configfilename) as theFile:
        readInTheFile = theFile.readlines()
        for thisLine in readInTheFile:
            #Split into config item and the data by the '='
            thisLineSplit = thisLine.split("=")
            #Check if the line starts with a '#' - if so ignore
            if not "#" in thisLineSplit[0][0]:
                if paramToGet in thisLineSplit[0]:
                    #Strip off the end spaces, quotes and new line char
                    paramValue = thisLineSplit[1].strip().strip('"')

                    #Convert the string True/False to explicit True/False
                    if paramValue == "True":
                        paramValue = True
                    if paramValue == "False":
                        paramValue = False

                    return paramValue

def getMainLoggingLevel():
  return readInConfigFile("MAINLOGGINGLEVEL")

def getFlaskLoggingLevel():
    return readInConfigFile("FLASKLOGGINGLEVEL")

def getRichConsoleBannerStyle():
  return readInConfigFile("richConsoleBannerStyle")

def getRichConsoleStyle():
  return readInConfigFile("richConsoleStyle")

def getTempStorageDirectory():
  return readInConfigFile("tempDirectory")

def getManagementInterface():
  return readInConfigFile("wirelessAccessPointNameForManagement")

def getManagementSSID():
  return readInConfigFile("wirelessAccessPointSSIDForManagement")

def getManagementPSK():
  return readInConfigFile("wirelessAccessPointPasswordForManagement")

def getIOTSSID():
  return readInConfigFile("wirelessAccessPointSSIDForIOT")

def getIOTPSK():
  return readInConfigFile("wirelessAccessPointPasswordForIOT")

def getIOTInterfaceGatewayIPAddress():
  return readInConfigFile("wirelessAccessPointIPForIOT")

def getManagementInterfaceGatewayIPAddress():
  return readInConfigFile("wirelessAccessPointIPForManagement")

def getMozillaCertsURL():
    return readInConfigFile("mozillaCertsURL")

def getRunWebApp():
    return readInConfigFile("webApp")

def getWebAppPort():
    return readInConfigFile("webAppPort")

def getRunConsoleApp():
    return readInConfigFile("consoleApp")

def getAWS_ACCESS_KEY_ID():
    return readInConfigFile("AWS_Access_key_ID")

def getAWS_SECRET_ACCESS_KEY():
    return readInConfigFile("AWS_Secret_access_key")

def getEmailAddressForACME():
    return readInConfigFile("letscrypt_email_address")

def getRoute53OwnedDomain():
    return readInConfigFile("route53_owned_domain")

def getIsThisTestMode():
    return readInConfigFile("standalonetestmode")
