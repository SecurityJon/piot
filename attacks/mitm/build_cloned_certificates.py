#############################################################################
#   This script clones and builds X509 certificates for MitmProxy to use
#############################################################################

import config as config
import subprocess
from datetime import datetime
import os
import numpy as numpyModule
import urllib.request
import re
import logging

######################################
#  Logging
######################################
log = logging.getLogger("rich")

# Download a set of CA certificates from mozilla into a file
def downloadMozillaCertificates(URL, filePath):
  log.debug("Saving Mozilla CA certificate bundle into {}".format(filePath))    
  with urllib.request.urlopen(URL) as response, open(filePath, 'wb') as out_file:
    data = response.read() # a `bytes` object
    out_file.write(data)

# Check if a URL actually has a certificate associated with it
# Returns FALSE if ther are any issues
def URLDefinatelyHasACertAndExists(URI):
  try:
    proc1 = subprocess.run(['openssl s_client -connect {}:443 -showcerts </dev/null'.format(URI)], stdout=subprocess.DEVNULL, shell=True, stderr=subprocess.DEVNULL, timeout=5)
  except subprocess.TimeoutExpired:
    #This took far too long to get a result, timeout and throw an error
    log.debug("Timed out obtaining certificate for {}".format(URI))
    return False      

  # Check for issues
  if proc1.returncode == 0:
    return True      
  else:
    log.debug("Error obtaining certificate for {}".format(URI))      
    return False


# Save a single certificate to a single file on disk
def downloadLegitLeafCertificateOver443(URI, certificatePath):
  log.debug("Getting Certificate for {}".format(URI))
  proc1 = subprocess.run(['openssl s_client -connect {}:443 -showcerts </dev/null'.format(URI)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  with open(certificatePath, "w") as outfile:
    proc2 = subprocess.run(['openssl x509 -outform pem'], input=proc1.stdout, stdout=outfile, shell=True, stderr=outfile)
  log.debug("Certificate written to {}".format(certificatePath))
    
# Save the entire certificate chain to a single file on disk
def downloadLegitCertificateChainOver443(URI, certificatePath):
  log.debug("Getting Certificate chain for {}".format(URI))        
  with open(certificatePath, "w") as outfile:
    proc1 = subprocess.run(['openssl s_client -connect {}:443 -showcerts -verify 5 </dev/null'.format(URI)], stdout=outfile, shell=True, stderr=outfile)
  log.debug("Certificate Chain written to {}".format(certificatePath))
  
# Take in a certificate chain from a single file on the disk
def splitCertificateChainToFindTheCA(certificatePath, caCertificateBundleLocation):
  log.debug("Reading Certificate Chain from {}".format(certificatePath))        
  f = open(certificatePath, "r")  
  #Split the chain into parts and add in the separator again  
  arrayOfCerts = []
  currentCertString = ""
  delim = "-----END CERTIFICATE-----"
  all_lines = f.readlines()  
  for line in all_lines:
    if not delim in line:
      currentCertString = currentCertString + line
    else:
      currentCertString = currentCertString + line
      arrayOfCerts.append(currentCertString)
      currentCertString = ""


  #Extract the directory from the certificate to parse, for writing files to later
  directoryToDumpArray = certificatePath.split("/")
  directoryToDumpArray[(len(directoryToDumpArray)) -1] = ""
  directoryToDump = "/".join(directoryToDumpArray)

  ##################################
  # DEBUG - dumps the certificate chain to disk
  #if DEBUG == True:
  #  print("Dumping Certificate Chain to {}".format(directoryToDump))
  #  loopy = 0
  #  print("Certificate Chain contains {} certificates".format(len(arrayOfCerts)))  
  #  for certMeBaby in arrayOfCerts:
  #    intermediateToWrite = open(directoryToDump + "level_" + str(loopy) + "InCertificateChain.pem", "w")
  #    intermediateToWrite.write(certMeBaby)
  #    intermediateToWrite.close()
  #    print("Written to disk {}".format(directoryToDump + "level_" + str(loopy) + "InCertificateChain.pem"))
  #    loopy = loopy + 1
  ##################################    
  
  
  #We now have the child leaf certificate and all intermediate certificates but NOT the root CA
  #as that certificate is not included in the chain we have downloaded
  #We now need to get the top intermediate certificate in our chain and extract out it's issuer        
  #because of the carving process we need to check where this
  topLevelCertificateInChain = ""
  if "-----END CERTIFICATE-----" in arrayOfCerts[len(arrayOfCerts) -1]:
    topLevelCertificateInChain = arrayOfCerts[len(arrayOfCerts) -1]
  else:
    topLevelCertificateInChain = arrayOfCerts[len(arrayOfCerts) -2]

  #Write the top level certificate to disk and extract it's issuer and subject
  intermediateToWrite = open(directoryToDump + "topLevelCertificateInChain.txt", "w")
  intermediateToWrite.write(topLevelCertificateInChain)
  intermediateToWrite.close()
  log.debug("Top level in chain written to {}".format(directoryToDump + "topLevelCertificateInChain.txt"))
  fullSubject = (extractSubjectFromCertificate(directoryToDump + "topLevelCertificateInChain.txt"))
  fullIssuer = (extractIssuerFromCertificate(directoryToDump + "topLevelCertificateInChain.txt"))
  log.debug("Top level chain certificate subject {}".format(fullSubject))
  log.debug("Top level chain certificate issuer {}".format(fullIssuer))
  
  #We now need to search the trusted root CA certificates that have been provided by Mozilla for the CA that issued this
  #certificate chain, so we can extract it's details
  log.debug("Searching Mozilla CA bundle for subject {}".format(fullSubject))
  resultsofCASearch = findMeTheCorrectCA(caCertificateBundleLocation, fullSubject)
  #CA Certificate found using Subject
  if not "not_here" in resultsofCASearch:
    log.debug("Found CA certificate using Subject field, the root CA for this site is {}".format(resultsofCASearch))
  else:
    log.debug("Subject not found, searching Mozilla CA bundle for using Issuer {}".format(fullIssuer))
    resultsofCASearch = findMeTheCorrectCA(caCertificateBundleLocation, fullIssuer)
    #CA Certificate found using Issuer
    if not "not_here" in resultsofCASearch:
      log.debug("Found CA certificate using Issuer field, the root CA for this site is {}".format(resultsofCASearch))
    #The CA certificate cannot be found, perhaps they're using a self-signed CA at the top
    #We grab the top level certificate in the chain and feed the location of that back instead
    else:
      #Use the location of the top level in the chain we extracted earlier, this should have enough for us to use
      resultsofCASearch = directoryToDump + "topLevelCertificateInChain.txt"
      log.debug("Could not find the Correct CA in the Mozilla CA bundle, using {} as the CA".format(resultsofCASearch))

  return resultsofCASearch



#Take a single file bundle of CAs from Mozilla and write them all out to individual files
def extractCAListFiles(caCertificateBundlePath, caBundleToDumpToPath):
  log.debug("Extracting CA certificate bundle from {} into {}".format(caCertificateBundlePath, caBundleToDumpToPath))            
  #Grab the bundle path
  f = open(caCertificateBundlePath, "r")  
  #Split the CAs into parts and add in the separator again
  arrayOfCerts = []
  currentCertString = ""
  delim = "-----END CERTIFICATE-----"
  all_lines = f.readlines()  
  for line in all_lines:
    if not delim in line:
      currentCertString = currentCertString + line
    else:
      currentCertString = currentCertString + line
      arrayOfCerts.append(currentCertString)
      currentCertString = ""
  
  #We now have all of the root CAs in a array, we'll dump each to disk and parse with openssl
  loopy = 0
  for thisCA in arrayOfCerts:
    caToWrite = open(caBundleToDumpToPath + str(loopy) + "_ca.pem", "w")
    caToWrite.write(thisCA)
    caToWrite.close()
    loopy = loopy + 1
  log.debug("{} CA certificates were extracted".format(len(arrayOfCerts)))

#This will search through CAs dumped on the filesystem, hunting for the correct one that issued a certificate by the subject field
#Returns the path on the disk that the CA certificate
def findMeTheCorrectCA(certificatesPath, subjectToFind):
  #Grab all of the root CAs
  for filename in os.listdir(certificatesPath):
    fullPath = os.path.join(certificatesPath, filename)
    with open(fullPath, 'r') as f:
      #Grab the Subject
      thisSubject = extractSubjectFromCertificate(fullPath)        
      if thisSubject == subjectToFind:
        log.debug("Found CA Certificate with subject {} at {}".format(subjectToFind, fullPath)) 
        return fullPath
        break
  #If after looking through all of the certificates we can't find one with the subject we want, return this 
  return "not_here"
   

def extractSubjectFromCertificate(certificatePath):
  command = 'openssl x509 -in {} -noout -subject'.format(certificatePath)
  #log.debug("Extracting Subject using command: {}".format(command))
  #proc1 = subprocess.run(['openssl x509 -in {} -noout -subject'.format(certificatePath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  proc1 = subprocess.run([command], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  fullString = proc1.stdout.decode().strip()
  #Strip the none needed part off
  bitToRemove = "subject="
  nextStringToProcess = fullString.replace(bitToRemove, "")
  #The final string to return
  finalStringToReturn = ""
  
  
  #Replace double quotes with something else temporarily so we can split
  subjectArray = []
  subjectArrayWithRandomCommasFixed = []
  subjectArraySplitByDoubleQuote = nextStringToProcess.split('"')
  #Convert to array
  numPyArrayOne = numpyModule.asarray(subjectArraySplitByDoubleQuote)
  #Find any item sandwiched between two others. That is the bit that was between quotes
  for i in range(len(numPyArrayOne)):
    #If iterator is even, just add back to a list
    if (i % 2) == 0:
      subjectArrayWithRandomCommasFixed.append(numPyArrayOne[i])
    else:    
      tempStringOne = numPyArrayOne[i]
      #Replace comma with a random string we can identify
      tempStringTwo = tempStringOne.replace(",", "IGNOREIGNOREIGNOREIGNORE")
      #We don't need to put the double quotes back in
      subjectArrayWithRandomCommasFixed.append(tempStringTwo) 
      #subjectArrayWithRandomCommasFixed.append("\"" + tempStringTwo + "\"")    
    
  #subjectArrayWithRandomCommasFixed now contains an array with errant commas replaced
  #We can not split this by commas to sort the string
  subjectArrayBackToString = "".join(subjectArrayWithRandomCommasFixed) 
  subjectArrayToSortCommasOut = subjectArrayBackToString.split(',')  
  
  stringThatJustNeedsOneLastReplacement = ""
  for subjectBit in subjectArrayToSortCommasOut:
    subjectBitSortedOut = ""
    #Sort out the spaces between the equals by splitting into an array
    #Split by the = into a new array
    subjectBitArray = subjectBit.split('=')
    #New array we'll append to
    newsubjectBitArray = []
    for subjectBitArraySplit in subjectBitArray:
      #Strip off extra spaces and append to new array
      newsubjectBitArray.append(subjectBitArraySplit.strip())
    #Combine everything together separated with a =
    subjectBitSortedOut = "=".join(newsubjectBitArray)
  
    stringThatJustNeedsOneLastReplacement = stringThatJustNeedsOneLastReplacement + "/" + subjectBitSortedOut

  #Finally we need to fix the corrections we did earlier
  finalStringToReturn = stringThatJustNeedsOneLastReplacement.replace("IGNOREIGNOREIGNOREIGNORE", ",")
  #log.debug("Subject extracted is {}".format(finalStringToReturn))
  return finalStringToReturn

#Takes in the subject/issuer of a certificate and carves out its CN
def extractCommonNameFromSubjectOrIssuer(fullSubject):
    fullSubjectArraySplit = fullSubject.split("/")
    CnToSplit = fullSubjectArraySplit[len(fullSubjectArraySplit) -1]
    commonnameToSplit = CnToSplit.split("=")
    commonname = commonnameToSplit[len(commonnameToSplit) -1]
    log.debug("Common name of Subject {}".format(commonname))
    return commonname


def buildaCA(clonedCAKeyPath, clonedCAConfigPath, clonedCACertificatePath, theRealCAPath, indexFilePath, serialFilePath):
    # First we'll create a custom directory to be used later for our CA bits
    # Then we're going to do here is to create a key for our CA
    # Then we're going to create a config file containing everything we need for our CA
    # Then we're going to create a CA certificate using that config and key
    # Then we'll return the name of the path where all of this is - we'll use hard coded names for our key/cert
    # For this we'll need a load of stuff from the cloned CA details
    
  serial = extractSerialFromCertificate(theRealCAPath)
  subject = extractSubjectFromCertificate(theRealCAPath)  
    
  #Build a CA config file
  caConfigFile = '''
    # OpenSSL CA configuration file
    [ ca ]
    default_ca = CA_default

    [ CA_default ]
    default_days = 365
    database = {}
    serial = {}
    default_md = sha256
    copy_extensions = copy
    unique_subject = no
    
    # Used to create the CA certificate.
    [ req ]
    prompt=no
    distinguished_name = distinguished_name
    x509_extensions = extensions

    [ distinguished_name ]
    organizationName = replace
    commonName = replace

    [ extensions ]
    keyUsage = critical,digitalSignature,nonRepudiation,keyEncipherment,keyCertSign
    basicConstraints = critical,CA:true,pathlen:1

    # Policy for signing LeafNodes
    [ signing_policy ]
    countryName                     = optional
    stateOrProvinceName             = optional
    localityName                    = optional
    organizationName                = optional
    organizationalUnitName          = optional
    commonName                      = supplied
    emailAddress                    = optional

    # Used to sign node certificates.
    [ signing_node_req ]
    keyUsage = critical,digitalSignature,keyEncipherment
    extendedKeyUsage = serverAuth,clientAuth
  '''.format(indexFilePath, serialFilePath, subject, subject)
  
  #Write the config file out to a file to use
  cacnfFilePath = clonedCAConfigPath
  filehandle = open(cacnfFilePath, 'w')
  filehandle.write(caConfigFile)
  filehandle.close()
  
  #Build the certificate request to get signed
  caCrtFilePath = clonedCACertificatePath
  buildingCommand = '''openssl req -config {}
             -x509 -new -nodes -key {}
             -sha1 -days 7062 
             -set_serial 0x{}
             -subj "{}"
             -out {}
             '''.format(cacnfFilePath, clonedCAKeyPath, serial, subject, clonedCACertificatePath)
  
  finalCommand = str(" ".join(buildingCommand.split()))
  proc1 = subprocess.run(finalCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
  log.debug("CA Cert created at {}".format(caCrtFilePath))      

    
#Create a CSR to be signed by our cloned CA
#def createClonedCSR(keyPath, certificatePath, finalCSROutputPath):
#  subject = extractSubjectFromCertificate(certificatePath)
#  SANs = extractSANsFromCertificate(certificatePath)
#  email = extractEmailFromCertificate(certificatePath)  
  
  #Reminder this might be needed
  #cd /home/jon/ into RNG
  #openssl rand -writerand .rnd
  
  #Build the certificate request to get signed
#  buildingCommand = '''openssl req -new -sha1 -nodes 
#             -key {}
#             -subj "{}"
#             -addext "subjectAltName={}"
#             -out {}
#             '''.format(keyPath, subject, SANs, finalCSROutputPath)

  
#  finalCommand = str(" ".join(buildingCommand.split()))
#  proc1 = subprocess.run(finalCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
#  print(finalCommand)
#  log.debug("CSR for {} created at {}".format(subject, finalCSROutputPath))      


def extractEmailFromCertificate(certificatePath):
  proc1 = subprocess.run(['openssl x509 -in {} -noout -email'.format(certificatePath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  fullString = proc1.stdout.decode().strip()
  #Strip the none needed part off
  bitToRemove = "email="
  finalStringToReturn = fullString.replace(bitToRemove, "")
  return finalStringToReturn

def extractIssuerFromCertificate(certificatePath):
  proc1 = subprocess.run(['openssl x509 -in {} -noout -issuer'.format(certificatePath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  fullString = proc1.stdout.decode().strip()
  #Strip the none needed part off
  bitToRemove = "issuer="
  nextStringToProcess = fullString.replace(bitToRemove, "")
  #The final string to return
  finalStringToReturn = ""
  #Split into an array defined by commas
  subjectArray = nextStringToProcess.split(',')
  for subjectBit in subjectArray:
    subjectBitSortedOut = ""
    #Sort out the spaces between the equals by splitting into an array
    #Split by the = into a new array
    subjectBitArray = subjectBit.split('=')
    #New array we'll append to
    newsubjectBitArray = []
    for subjectBitArraySplit in subjectBitArray:
      #Strip off extra spaces and append to new array
      newsubjectBitArray.append(subjectBitArraySplit.strip())
    #Combine everything together separated with a =
    subjectBitSortedOut = "=".join(newsubjectBitArray)
  
    finalStringToReturn = finalStringToReturn + "/" + subjectBitSortedOut
  return finalStringToReturn

def extractSerialFromCertificate(certificatePath):
  proc1 = subprocess.run(['openssl x509 -in {} -noout -serial'.format(certificatePath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  fullString = proc1.stdout.decode().strip()
  #Strip the none needed part off
  bitToRemove = "serial="
  finalStringToReturn = fullString.replace(bitToRemove, "")
  return finalStringToReturn

def extractStartDateFromCertificate(certificatePath):
  proc1 = subprocess.run(['openssl x509 -in {} -noout -startdate'.format(certificatePath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  fullString = proc1.stdout.decode().strip()
  #Strip the none needed part off
  bitToRemove = "notBefore="
  dateStringToProcess = fullString.replace(bitToRemove, "")
  
  #Convert the date into the format we'll need later  
  datetime_object = datetime.strptime(dateStringToProcess, '%b %d %H:%M:%S %Y %Z')
  finalStringToReturn = datetime_object.strftime("%Y%m%d%H%M%S")
  finalStringToReturn = finalStringToReturn + "Z"
  
  return finalStringToReturn

def extractEndDateFromCertificate(certificatePath):
  proc1 = subprocess.run(['openssl x509 -in {} -noout -enddate'.format(certificatePath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  fullString = proc1.stdout.decode().strip()
  #Strip the none needed part off
  bitToRemove = "notAfter="
  dateStringToProcess = fullString.replace(bitToRemove, "")
  log.debug("End date of certificate being processed: {}".format(dateStringToProcess))
  
  #Convert the date into the format we'll need later  
  datetime_object = datetime.strptime(dateStringToProcess, '%b %d %H:%M:%S %Y %Z')
  finalStringToReturn = datetime_object.strftime("%Y%m%d%H%M%S")
  finalStringToReturn = finalStringToReturn + "Z"
  
  return finalStringToReturn

def extractSANsFromCertificate(certificatePath):
  proc1 = subprocess.run(['openssl x509 -in {} -noout -ext subjectAltName'.format(certificatePath)], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)
  fullString = proc1.stdout.decode().strip()
  #Strip the none needed part off
  bitToRemove = "X509v3 Subject Alternative Name:"
  headRemoved = fullString.replace(bitToRemove, "").strip()
  #Remove anything that isn't a DNS or IP entry
  finalArray = []
  finalStringToReturn = ""
  sanList = headRemoved.split(",")
  for san in sanList:
    sanSplitAgain = san.split(":")
    if sanSplitAgain[0].strip() == "DNS":
      finalArray.append(san)
    if sanSplitAgain[0].strip() == "IP Address":
      newSANArray = []
      newSANArray.append("IP")
      for i in range(len(sanSplitAgain)):
        if not i == 0:
          newSANArray.append(sanSplitAgain[i])     
      finalArray.append(":".join(newSANArray))
      
  finalStringToReturn = ",".join(finalArray)
  return finalStringToReturn

#Crete a private key, using the same key size and type
#TO DO - DO THIS
def createPrivateKey(keyPath):
  finalCommand = 'openssl genrsa -out {} 4096'.format(keyPath)
  log.debug("Creating private key at {}".format(keyPath))
  log.debug("Command to build private key: {}".format(finalCommand))
  proc1 = subprocess.run([finalCommand], stdout=subprocess.PIPE, shell=True, stderr=subprocess.DEVNULL)

#Create a CSR to be signed by our cloned CA
def createClonedCSR(keyPath, certificatePath, finalCSROutputPath, leafCertCloneCSRCNFPath):
    
  #Build a config file
  cnfConfigFile = '''
    # OpenSSL CA configuration file
    [ req ]
    #default_bits = 2048    
    distinguished_name = leafCert

    [ leafCert ]
    countryName                     = optional
    stateOrProvinceName             = optional
    localityName                    = optional
    organizationName                = optional
    organizationalUnitName          = optional
    commonName                      = optional
    emailAddress                    = optional    
  '''.format()
  
  #Write the config file out to a file to use  
  filehandle = open(leafCertCloneCSRCNFPath, 'w')
  filehandle.write(cnfConfigFile)
  filehandle.close()    
    
    
  #Extract the details from the leaf certificate 
  subject = extractSubjectFromCertificate(certificatePath)
  SANs = extractSANsFromCertificate(certificatePath)
  email = extractEmailFromCertificate(certificatePath)  
  
  #Reminder this might be needed
  #cd /home/jon/ into RNG
  #openssl rand -writerand .rnd
  
  subjectToWrite = ""
  sansToWrite = ""
  emailToWrite = ""

  if not subject == "":
      subjectToWrite = "-subj \'" + subject + "\'"
  if not SANs == "":
      sansToWrite = "-addext \'subjectAltName=" + SANs + "\'"
  if not email == "":
      emailToWrite = "-email \'" + email + "\'"
  
  #Build the certificate request to get signed
  #buildingCommand = '''openssl req -new -sha256 -nodes
  #           -key {}
  #           {}
  #           {}
  #           {}
  #           -out {}
  #           -config {}
  #           '''.format(keyPath, subjectToWrite, sansToWrite, emailToWrite, finalCSROutputPath, leafCertCloneCSRCNFPath)

  #Build the certificate request to get signed
  #REMOVED EMAIL AS IT WAS CAUSING ISSUES
  buildingCommand = '''openssl req -new -sha256 -nodes 
             -key {}
             {}
             {}
             -out {}
             -config {}
             '''.format(keyPath, subjectToWrite, sansToWrite, finalCSROutputPath, leafCertCloneCSRCNFPath)

  
  finalCommand = str(" ".join(buildingCommand.split()))
  log.debug("Command to build CSR {}".format(finalCommand))
  proc1 = subprocess.run(finalCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
  log.debug("CSR for {} created at {}".format(subject, finalCSROutputPath))  


# Sign a CSR as our fake CA, using X509 which doesn't copy over ALTSANNAMES
# Kept in for debugging, don't use this one
def signARequestAsACAUsingX509(legitLeafNodePath, csrPath, caPublicKeyPath, caPrivateKeyPath, signedCertificateoutputPath):
  startDate = extractStartDateFromCertificate(legitLeafNodePath)
  endDate = extractEndDateFromCertificate(legitLeafNodePath)
  serial = extractSerialFromCertificate(legitLeafNodePath)  

  #Build the command
  buildingCommand = '''openssl x509 -req 
             -in {}
             -CA {}
             -CAkey {}
             -set_serial 0x{}
             -out {}
             '''.format(csrPath, caPublicKeyPath, caPrivateKeyPath, serial, signedCertificateoutputPath)

  
  finalCommand = str(" ".join(buildingCommand.split()))
  proc1 = subprocess.run(finalCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
  log.debug("Signed Certificate created at {}".format(signedCertificateoutputPath))
  
  
# Sign a CSR as our fake CA, using X509 which doesn't copy over ALT SAN NAMES
# Kept in for debugging, don't use this one
def signARequestAsACAUsingCA(legitLeafNodePath, csrPath, caPublicKeyPath, caPrivateKeyPath, clonedCAConfigPath, signedCertificateoutputPath, allCertificatesoutputPath):           
  startDate = extractStartDateFromCertificate(legitLeafNodePath)
  endDate = extractEndDateFromCertificate(legitLeafNodePath)

  #Build the command
  buildingCommand = '''openssl ca 
             -in {}
             -cert {}
             -keyfile {}
             -config {}            
             -out {}
             -outdir {}
             -batch
             -extensions signing_node_req
             -policy signing_policy
             '''.format(csrPath, caPublicKeyPath, caPrivateKeyPath, clonedCAConfigPath, signedCertificateoutputPath, allCertificatesoutputPath)
  
  finalCommand = str(" ".join(buildingCommand.split()))
  proc1 = subprocess.run(finalCommand, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
  log.debug("Command to sign CSR: {}".format(finalCommand))
  log.debug("Signed Certificate created at {}".format(signedCertificateoutputPath))        
  
  
#Method to take in a serial, convert it to integer, decrease it by one, hex it up and return
def decreaseTheHexSerial(serial):
  #Split out serial into chunks of four digits to deal with
  serialInFourChunksArray = [serial[i:i+4] for i in range(0, len(serial), 4)]
  numpyArray = numpyModule.asarray(serialInFourChunksArray)
  #numpyArray = numpyModule.array(serialInFourChunksArray)
  #You can access the last element in an numpy array by using a negative number
  lastBytesOfSerial = numpyArray[-1]
  #Strip off the single quotes
  lastBytesOfSerial.replace('\'', '')
  serialInDecimal = int(lastBytesOfSerial, 16)
  serialDecreased = serialInDecimal -1
  serialToHexAgain = hex(serialDecreased).split('x')[-1]
  #Add the hex back into the array
  numpyArray[-1] = serialToHexAgain
  #Change the array back into a single string
  finalSerial = ""
  serialBackAsAList = numpyArray.tolist()
  for element in serialBackAsAList:
    element.replace('\'', '')
    finalSerial = finalSerial + element
  
  log.debug("Serial {} for certificate has been decreased to {}".format(serial, finalSerial))        
  return finalSerial


def createSerialFile(filePath, serial):
  serialToWrite = open(filePath, "w")
  serialToWrite.write(serial)
  serialToWrite.close()
  log.debug("Serial File created at {}".format(filePath))
  return filePath


def smashAllOfTheCertsTogetherForMITMProxy(leafCertCloneKeyPath, signedCertificateoutputPath, clonedCACertificatePath, finalClonedCertificatePathForMITMProxy, websiteToGet):
  #Open the final file to write
  finalFileToWrite = open(finalClonedCertificatePathForMITMProxy, "w")

  #Read and write the private key
  with open(leafCertCloneKeyPath, 'r') as file:
    contents = file.read()
    finalFileToWrite.write(contents)
    file.close()
  
  #Read and write the signed certificate
  with open(signedCertificateoutputPath, 'r') as file:
    contents = file.read()      
    finalFileToWrite.write(contents)
    file.close()    

  #Read and write the CA certificate
  with open(clonedCACertificatePath, 'r') as file:
    contents = file.read()      
    finalFileToWrite.write(contents)
    file.close()    

  #Write the file to disk
  finalFileToWrite.close()
  log.debug("Signed Cloned File for {} created at {}".format(websiteToGet, finalClonedCertificatePathForMITMProxy))

