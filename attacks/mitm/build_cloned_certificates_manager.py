#############################################################################
#   This script manages cloning X509 certificates for MitmProxy to use
#############################################################################

import attacks.mitm.letsencrypt_route53_fake_certificates as lefcs
import functions.functions as functions
import config
from attacks.mitm import build_cloned_certificates


#Download and unpack CA certificates to a path, returns the path of the files
def downloadAndUnpackCACertificates(directoryPath):
  topLevelCertificatesRootDirectory = functions.makeTemporaryDirectories(directoryPath, "tempCertificateCloningDir")
  #Get CA certs from Mozilla
  caDirectory = functions.makeTemporaryDirectories(topLevelCertificatesRootDirectory, "caCertificates")
  mozillaCertsFilePath =  caDirectory + "downloadedMozillaCertificatesPacked.pem"
  mozillaCertsURL = "https://ccadb-public.secure.force.com/mozilla/IncludedRootsPEMTxt?TrustBitsInclude=Websites"
  build_cloned_certificates.downloadMozillaCertificates(mozillaCertsURL, mozillaCertsFilePath)
  #Dump CA certs to path
  caDumpDirectory = functions.makeTemporaryDirectories(caDirectory, "caCertificatesUnpacked")
  build_cloned_certificates.extractCAListFiles(mozillaCertsFilePath, caDumpDirectory)
  return caDumpDirectory

def cloneURI(URI, directoryPath, caDumpDirectoryPath):
  #Confirm the website exists, can be reached and we get a decent cert
  if build_cloned_certificates.URLDefinatelyHasACertAndExists(URI) == True:
    topLevelCertificatesRootDirectory = functions.makeTemporaryDirectories(directoryPath, "tempCertificateCloningDir")      
    #Create required directories
    certificateRootDirectory = functions.makeTemporaryDirectories(topLevelCertificatesRootDirectory, URI)
    #Download certificate chain for a website
    legitCertChainRootDirectory = functions.makeTemporaryDirectories(certificateRootDirectory, "legitCertificates")
    chainFileLocation = legitCertChainRootDirectory + "fullCertificateChain.pem"
    build_cloned_certificates.downloadLegitCertificateChainOver443(URI, chainFileLocation)
    #Download just the leaf node
    leafFileLocation = legitCertChainRootDirectory + "justLeafCertificate.pem"
    build_cloned_certificates.downloadLegitLeafCertificateOver443(URI, leafFileLocation)

    #Build a self-signed CA from a real one
    theRealCAPath = build_cloned_certificates.splitCertificateChainToFindTheCA(chainFileLocation, caDumpDirectoryPath)
    caCloneRootDirectory = functions.makeTemporaryDirectories(certificateRootDirectory, "CAClone")
    clonedCAConfigPath = caCloneRootDirectory + "ca.cnf"
    clonedCACertificatePath = caCloneRootDirectory  + "ca.crt"
    clonedCAKeyPath = caCloneRootDirectory + "ca.key"
    build_cloned_certificates.createPrivateKey(clonedCAKeyPath)
    #Build a CA set of files
    #Make a indexDB file for the CA to write to
    indexDBPath = functions.makeTemporaryFiles(caCloneRootDirectory + "index.db")
    #Create a serial file and populate it with a serial thats one before the one we need
    leafNodeSerialToUse = build_cloned_certificates.extractSerialFromCertificate(leafFileLocation)
    #decreasedSerial = build_cloned_certificates.decreaseTheHexSerial(leafNodeSerialToUse)
    serialFilePath = signedCertificateoutputPath = caCloneRootDirectory + "serial.txt"
    build_cloned_certificates.createSerialFile(serialFilePath, leafNodeSerialToUse)
    build_cloned_certificates.buildaCA(clonedCAKeyPath, clonedCAConfigPath, clonedCACertificatePath, theRealCAPath, indexDBPath, serialFilePath)

    #Build a CSR to be signed
    leafCertCloneDirectory = functions.makeTemporaryDirectories(certificateRootDirectory, "leafCertClone")
    leafCertCloneKeyPath = leafCertCloneDirectory + "key.key"
    build_cloned_certificates.createPrivateKey(leafCertCloneKeyPath)
    leafCertCloneCSRPath = leafCertCloneDirectory + "csr.csr"
    leafCertCloneCSRCNFPath = leafCertCloneDirectory + "csr.cnf"
    build_cloned_certificates.createClonedCSR(leafCertCloneKeyPath, leafFileLocation, leafCertCloneCSRPath, leafCertCloneCSRCNFPath)

    #Sign CSR with CA
    finalClonedCertificateDirectory = functions.makeTemporaryDirectories(certificateRootDirectory, "finalClonedCertificate")
    signedCertificateoutputPath = finalClonedCertificateDirectory + "clonedSignedCertificate.pem"
    build_cloned_certificates.signARequestAsACAUsingCA(leafFileLocation, leafCertCloneCSRPath, clonedCACertificatePath, clonedCAKeyPath, clonedCAConfigPath, signedCertificateoutputPath, caCloneRootDirectory)

    #Combine the private and public certificates, intermediate CAs and the root CA in one file
    finalClonedCertificatePathForMITMProxy = finalClonedCertificateDirectory + URI
    build_cloned_certificates.smashAllOfTheCertsTogetherForMITMProxy(leafCertCloneKeyPath, signedCertificateoutputPath, clonedCACertificatePath, finalClonedCertificatePathForMITMProxy, URI)

    finalListOfEverything = [URI, finalClonedCertificatePathForMITMProxy]
    return finalListOfEverything
  #URI does not exist
  else:
    return []

#Create a certificate chain using LetsEncrypt
def cloneURIUsingLetsEncrypt(URI, directoryPath):
    #Confirm the website exists, can be reached and we get a decent cert
    if build_cloned_certificates.URLDefinatelyHasACertAndExists(URI) == True:
        route53Domain = config.getRoute53OwnedDomain()

        topLevelCertificatesRootDirectory = functions.makeTemporaryDirectories(directoryPath, "tempCertificateCloningDir")      
        #Create required directories
        fullNameOfURI = URI + "." + route53Domain
        certificateRootDirectory = functions.makeTemporaryDirectories(topLevelCertificatesRootDirectory, fullNameOfURI)
        
        #Download just the leaf node for a website
        legitCertChainRootDirectory = functions.makeTemporaryDirectories(certificateRootDirectory, "legitCertificates")
        leafFileLocation = legitCertChainRootDirectory + "justLeafCertificate.pem"
        build_cloned_certificates.downloadLegitLeafCertificateOver443(URI, leafFileLocation)

        #Build a CSR to be signed
        leafCertCloneDirectory = functions.makeTemporaryDirectories(certificateRootDirectory, "leafCertClone")
        leafCertCloneKeyPath = leafCertCloneDirectory + "key.key"
        build_cloned_certificates.createPrivateKey(leafCertCloneKeyPath)
        leafCertCloneCSRPath = leafCertCloneDirectory + "csr.csr"
        leafCertCloneCSRCNFPath = leafCertCloneDirectory + "csr.cnf"
        lefcs.createClonedCSR(leafCertCloneKeyPath, leafFileLocation, leafCertCloneCSRPath, leafCertCloneCSRCNFPath)        
        

        #Delete the certificate if it exists within LetsEncrypt
        lefcs.deleteCertificateFromLetsEncrypt(URI)

        #Create Signed Certificate using CSR
        letsEncryptDownloadedFilesDirectory = functions.makeTemporaryDirectories(certificateRootDirectory, "letsEncryptCertificates")
        signingResult = lefcs.createCertificateUsingCSR(leafCertCloneCSRPath, letsEncryptDownloadedFilesDirectory)

        if signingResult[0] == "success":
            signedCertificateoutputPath = signingResult[1]
            route53Domain = config.getRoute53OwnedDomain()
            finalClonedCertificateDirectory = functions.makeTemporaryDirectories(certificateRootDirectory, "finalClonedCertificate")
            finalClonedCertificatePathForMITMProxy = finalClonedCertificateDirectory + URI + "." + route53Domain
            #Create the final certificate with key
            lefcs.smashKeyAndChainTogetherForMITMProxy(leafCertCloneKeyPath, signedCertificateoutputPath, finalClonedCertificatePathForMITMProxy, URI)
            
            finalListOfEverything = [URI, finalClonedCertificatePathForMITMProxy]
            return finalListOfEverything        
        #Something went wrong with the certificate creation process
        else:
            return []
    #Cannot get a certificate for this URI
    else:
        return []




