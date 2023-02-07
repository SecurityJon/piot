# LetsEncrypt and Route53 certificate builder

import os
import config as config
import logging
import subprocess
from attacks.mitm import build_cloned_certificates
from functions import functions

####################################
# Setting up logging and console output
####################################
log = logging.getLogger("rich")


#Requirements
# Create a new IAM policy with the required settings
# Create a new IAM user and attach policy at the end of the creation process
# Get the sets of keys and copy into the config here


def setEnvironmentVariables():
    AWS_ACCESS_KEY_ID = config.getAWS_ACCESS_KEY_ID()
    AWS_SECRET_ACCESS_KEY = config.getAWS_SECRET_ACCESS_KEY()
    os.environ['AWS_ACCESS_KEY_ID'] = AWS_ACCESS_KEY_ID
    os.environ['AWS_SECRET_ACCESS_KEY'] = AWS_SECRET_ACCESS_KEY    
    
def createCertificateUsingCSR(csrPath, letsEncryptDownloadedFilesDirectory):
    setEnvironmentVariables()
    acmeEmailAddress = config.getEmailAddressForACME()

    #Check if a certificate was created
    wasSuccessful = False
    certificatePath = ""
    keyPath = ""

    #Final file locations
    chainFileLocation = letsEncryptDownloadedFilesDirectory + "fullCertificateChain.pem"
    leafFileLocation = letsEncryptDownloadedFilesDirectory + "justLeafCertificate.pem"
    intermediaryChainFileLocation = letsEncryptDownloadedFilesDirectory + "intermediaryChainCertificate.pem"

    command = 'certbot certonly --dns-route53 --register-unsafely-without-email --dns-route53-propagation-seconds 10 --csr {} -m {} --agree-tos --non-interactive --cert-path {} --fullchain-path {} --chain-path {}'.format(csrPath, acmeEmailAddress, leafFileLocation, chainFileLocation, intermediaryChainFileLocation)
    log.debug("Certificate Creation Command Command: {}".format(command))
    proc1 = subprocess.run([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    commandoutput = proc1.stdout.decode().strip().splitlines()
    
    #Look through the result looking for the paths of the certificate and key
    for line in commandoutput:
        #Check to see if we get a success message, this will come before the paths
        if "Successfully received certificate." in line:
            wasSuccessful = True
        #Split the line by the : delim and check for any lines that have a success message and then the path
        lineSplit = line.split(':')
        if len(lineSplit) == 2:
            if "Certificate is saved at" in lineSplit[0]:
                pathOfCertificateNotStripped = lineSplit[1]
                certificatePath = pathOfCertificateNotStripped.strip()
            if "Full certificate chain is saved at" in lineSplit[0]:
                pathOfCertificateNotStripped = lineSplit[1]
                certificatePath = pathOfCertificateNotStripped.strip()
    
    #If there was an error, print it
    if wasSuccessful == False:
        log.error("Failure to create LetsEncrypt Certificate: {}".format(commandoutput))
        returnedList = ["error", certificatePath]
        return returnedList
    if wasSuccessful == True:
        returnedList = ["success", certificatePath]
        log.debug("Certificate Path: {}".format(certificatePath))        
        log.debug("Full Certificate Chain Path: {}".format(certificatePath))               
        return returnedList


#Use Certbot to create a certificate, using a URI, not a CSR
def createCertificateUsingURI(URI):   
    acmeEmailAddress = config.getEmailAddressForACME()
    route53Domain = config.getRoute53OwnedDomain()

    #Check if a certificate was created
    wasSuccessful = False
    certificatePath = ""
    keyPath = ""
    
    #Command to run
    command = 'certbot certonly --dns-route53 --dns-route53-propagation-seconds 10 -d {}.{} -m {} --agree-tos --non-interactive'.format(URI, route53Domain, acmeEmailAddress)
    log.debug("Certificate Creation Command Command: {}".format(command))
    proc1 = subprocess.run([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    commandoutput = proc1.stdout.decode().strip().splitlines()
    
    #Look through the result looking for the paths of the certificate and key
    for line in commandoutput:
        #Check to see if we get a success message, this will come before the paths
        if "Successfully received certificate." in line:
            wasSuccessful = True
        #Split the line by the : delim and check for any lines that have a success message and then the path
        lineSplit = line.split(':')
        if len(lineSplit) == 2:
            if "Certificate is saved at" in lineSplit[0]:
                pathOfCertificateNotStripped = lineSplit[1]
                certificatePath = pathOfCertificateNotStripped.strip()

            if "Key is saved at" in lineSplit[0]:
                pathOfKeyNotStripped = lineSplit[1]
                keyPath = pathOfKeyNotStripped.strip()
    
    #If there was an error, print it
    if wasSuccessful == False:
        log.error("Failure to create LetsEncrypt Certificate: {}".format(commandoutput))
        returnedList = ["error", certificatePath, keyPath]
        return returnedList
    if wasSuccessful == True:
        returnedList = ["success", certificatePath, keyPath]
        log.debug("Key Path: {}".format(keyPath))   
        log.debug("Certificate Path: {}".format(certificatePath))               
        return returnedList

#Delete a certificate from LetsEncrypt
def deleteCertificateFromLetsEncrypt(URI):
    route53Domain = config.getRoute53OwnedDomain()
    
    #Command to run
    command = 'certbot delete --cert-name {}.{} --non-interactive'.format(URI, route53Domain)
    log.debug("Certificate Deletion Command Command: {}".format(command))
    proc1 = subprocess.run([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    commandoutput = proc1.stdout.decode().strip().splitlines()
    log.debug(commandoutput)
    
    
#Create a CSR to be signed by our cloned CA
#This one doesn't create SANs, just the modified subject name
def createClonedCSR(keyPath, certificatePath, finalCSROutputPath, leafCertCloneCSRCNFPath):

  #Grab the root domain we own
  route53Domain = config.getRoute53OwnedDomain()
  
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
  extractedSubject = build_cloned_certificates.extractSubjectFromCertificate(certificatePath)
  email = build_cloned_certificates.extractEmailFromCertificate(certificatePath)

  #Add our Route53 domain to the CN of the subject
  subject = replaceCNwithOurCN(extractedSubject)
  
  #Reminder this might be needed
  #cd /home/jon/ into RNG
  #openssl rand -writerand .rnd
  
  subjectToWrite = ""
  sansToWrite = ""
  emailToWrite = ""
  if not subject == "":
      subjectToWrite = "-subj \'" + subject + "\'"
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
  
  
def smashKeyAndChainTogetherForMITMProxy(leafCertCloneKeyPath, signedCertificateoutputPath, finalClonedCertificatePathForMITMProxy, websiteToGet):
  #Grab the root domain we own
  route53Domain = config.getRoute53OwnedDomain()
  
  #Open the final file to write
  finalFileToWrite = open(finalClonedCertificatePathForMITMProxy, "w")

  #Read and write the private key
  with open(leafCertCloneKeyPath, 'r') as file:
    contents = file.read()
    finalFileToWrite.write(contents)
    file.close()
  
  #Read and write the signed certificate chain
  with open(signedCertificateoutputPath, 'r') as file:
    contents = file.read()      
    finalFileToWrite.write(contents)
    file.close()     

  #Write the file to disk
  finalFileToWrite.close()
  webSiteWeClonedFullName = websiteToGet + "." + route53Domain
  log.debug("Signed Cloned File for {} created at {}".format(webSiteWeClonedFullName, finalClonedCertificatePathForMITMProxy))  

#Take the subject of a certificate and replace the CN with our new one
def replaceCNwithOurCN(subject):
    finalSubject = ""
    subjectSplit = subject.split("/")
    for theElements in subjectSplit:
        #Ignore blanks
        if "" == theElements:
            ignore = "ignore"
        #Check if we have a CN
        elif "CN=" in theElements:
            # Grab the root domain we own
            route53Domain = config.getRoute53OwnedDomain()
            newElement = theElements + "." + route53Domain
            finalSubject = finalSubject + "/" + newElement
        else:
            finalSubject = finalSubject + "/" + theElements
    return finalSubject