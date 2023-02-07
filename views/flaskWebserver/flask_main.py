#Flask Main File
from flask import Flask, render_template, jsonify, redirect, url_for, send_file
import sys
import logging
# appending the directory of the main app
# in the sys.path list
sys.path.append('/')
import config as config

#This is used for creating dummy data for testing, a dummy controller is created
standalonetestmode = config.getIsThisTestMode()
if standalonetestmode == True:
    import test.testcontroller as controller
else:
    import controller as controller



app = Flask(__name__)

#Redirects to the home screen
def redirectToHomePage():
    print("WE SHOULD BE REDIRECTING TO THE HOME PAGE")
    #Except this is broken to death so instead just serve the home page
    #return redirect(url_for('index'))
    
    #EXCEPT THIS DOESNT WORK EITHER ARRGGGGGG
    index()

#Check if a device has been found and the user can proceed
#If not, return the user to the home page
def isLoadedAndReadyToGo():
    devicesIP = controller.checkforIPAddressAcquisition()
    if devicesIP is not None:        
        nmapStatus = controller.checkNMAP()
        if nmapStatus == "notstarted":
            controller.startNMAP()
        return True
    else:
        return False

@app.route("/")
def index():
    wifiname = config.getIOTSSID()
    wifipassword = config.getIOTPSK()
    return render_template("home.html", psk=wifipassword, ssid=wifiname, pagename="Welcome!")

@app.route("/starteverything")
def starteverything():    
    return render_template("setupdone.html", pagename="Setup")

@app.route("/iotdevices")
def getIOTDevices():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()
    return render_template("iotdevices.html", pagename="Devices")        

@app.route("/api/iotdevices")
def apiGetIOTDevices():
    if not isLoadedAndReadyToGo() == True:
        return jsonify(data="")
    else:    
        devicesIP = controller.checkforIPAddressAcquisition()
        return jsonify(data=devicesIP)


@app.route("/api/iotdevicesfulldetails")
def getIOTDevicesFullDetails():
    if not isLoadedAndReadyToGo() == True:
        return jsonify(data=None)
    else:
        devicesFullDetails = controller.getIOTDeviceDetails()
        return jsonify(data=devicesFullDetails)

@app.route("/dnsentries")
def getDNSEntriesSeen():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()

    returnedImmediateDNSEntriesSeen = controller.getImmediateDNSEntriesSeen()
    if returnedImmediateDNSEntriesSeen is None:
        immediateDNSEntriesSeen = []
    else:
        immediateDNSEntriesSeen = returnedImmediateDNSEntriesSeen

    return render_template("dns.html", pagename="DNS", data=immediateDNSEntriesSeen)

@app.route("/api/dnsentries")
def apiGetDNSEntriesSeen():
    if not isLoadedAndReadyToGo() == True:
        return jsonify([])    
    dnsEntriesSeen = controller.getDNSEntriesSeen()    
    return jsonify(dnsEntriesSeen)

@app.route("/mdnsentries")
def getmDNSEntriesSeen():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()

    returnedImmediatemDNSEntriesSeen = controller.getImmediatemDNSEntriesSeen()
    if returnedImmediatemDNSEntriesSeen is None:
        immediatemDNSEntriesSeen = []
    else:
        immediatemDNSEntriesSeen = returnedImmediatemDNSEntriesSeen

    return render_template("mdns.html", pagename="mDNS", data=immediatemDNSEntriesSeen)

@app.route("/api/mdnsentries")
def apiGetmDNSEntriesSeen():
    if not isLoadedAndReadyToGo() == True:
        return jsonify([])
    mdnsEntriesSeen = controller.getmDNSEntriesSeen()
    return jsonify(mdnsEntriesSeen)


@app.route("/snientries")
def getSNIsSeen():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()

    returnedImmediateSNIEntriesSeen = controller.getImmediateSNIsSeen()
    if returnedImmediateSNIEntriesSeen is None:
        immediateSNIEntriesSeen = []
    else:
        immediateSNIEntriesSeen = returnedImmediateSNIEntriesSeen

    return render_template("sni.html", pagename="Server Name Indications", data=immediateSNIEntriesSeen)

@app.route("/api/snientries")
def apiGetSNIsSeen():
    if not isLoadedAndReadyToGo() == True:
        return jsonify([])
    sniEntriesSeen = controller.getSNIsSeen()
    return jsonify(sniEntriesSeen)


@app.route("/conversations")
def getConversations():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()

    conversations = controller.getImmediateIOTConversations()
    if conversations is None:
        conversations = [[]]
    return render_template("conversations.html", pagename="Network Conversations", data=conversations)

@app.route("/api/conversations")
def apigetConversations():
    if not isLoadedAndReadyToGo() == True:
        return jsonify([])
    conversations = controller.getIOTConversations()
    return jsonify(conversations)


@app.route("/api/ciphersuites")
def apiGetCipherSuitesOffered():
    if not isLoadedAndReadyToGo() == True:
        return jsonify([[]])
    ciphersuitesSeen = controller.getCipherSuitesUsed()
    if ciphersuitesSeen is None:
        ciphersuitesSeen = [[]]
    return jsonify(ciphersuitesSeen)

@app.route("/ciphersuites")
def getCipherSuitesOffered():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()
    ciphersuitesSeen = controller.getImmediateCipherSuitesUsed()
    if ciphersuitesSeen is None:
        ciphersuitesSeen = [[]]
    return render_template("ciphersuites.html", pagename="Cipher Suites Used", data=ciphersuitesSeen)

@app.route("/nmap")
def runNMAP():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()    
    return render_template("nmap.html", pagename="NMAP")

@app.route("/api/nmapstatus")
def checkNMAP():
    nmapStatus = controller.checkNMAP()
    return jsonify(nmapStatus)

@app.route("/api/nmap")
def getNMAPResults():
    if not isLoadedAndReadyToGo() == True:
        return jsonify([])    
    nmapResults = controller.getNMAPResults()
    return jsonify(nmapResults)

@app.route("/mitmProxyDefaultMode")
def mitmProxyDefaultMode():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()    
    ismitmproxyrunning = controller.checkIsMitmProxyDefaultModeRunning()
    return render_template("mitmProxyDefaultMode.html", pagename="Basic Man-in-the-midddle", ismitmproxycurrentlyrunning=ismitmproxyrunning)

@app.route("/api/mitmProxyDefaultMode")
def apiMitmProxyDefaultMode():
    if not isLoadedAndReadyToGo() == True:
        return jsonify([])    
    controller.startMITMProxyDefaultMode()
    controller.getMiTMProxyHTTPSConvos()
    return ""

@app.route("/api/getMiTMProxyConvos")
def apiGetMiTMProxyConvos():
    if not isLoadedAndReadyToGo() == True:
        return jsonify([])    
    return jsonify(controller.getMiTMProxyHTTPSConvos())


@app.route("/mitmProxyCloneMode")
def mitmProxyCloneMode():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()    
    ismitmproxyrunning = controller.checkIsMitmProxyCloneModeRunning()
    return render_template("mitmProxyCloneMode.html", pagename="Advanced Man-in-the-midddle", ismitmproxycurrentlyrunning=ismitmproxyrunning)

@app.route("/api/mitmProxyCloneMode")
def apimitmProxyCloneMode():
    if not isLoadedAndReadyToGo() == True:
        return jsonify("[]")    
    controller.startMITMProxyCloneMode()
    controller.getMiTMProxyHTTPSConvos()
    return ""

@app.route("/mitmProxyLetsEncryptCloneMode")
def mitmProxyLetsEncryptCloneMode():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()
    ismitmproxyrunning = controller.checkIsMitmProxyLetsEncryptCloneModeRunning()
    return render_template("mitmProxyLetsEncryptCloneMode.html", pagename="Expert Man-in-the-midddle", ismitmproxycurrentlyrunning=ismitmproxyrunning)

@app.route("/api/mitmProxyLetsEncryptCloneMode")
def apimitmProxyLetsEncryptCloneMode():
    if not isLoadedAndReadyToGo() == True:
        return jsonify("[]")
    controller.startMITMProxyLetsEncryptCloneMode()
    controller.getMiTMProxyHTTPSConvos()
    return ""

@app.route("/stopMiTMProxy")
def killMitmProxyProcess():    
    controller.killMitmProxyProcess()
    return ""

@app.route("/networktraffic")
def networkTraffic():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()    
    networkdump = controller.getRawTSharkDump()
    return render_template("networktraffic.html", pagename="Network Traffic", data=networkdump)


@app.route("/downloadpcap")
def downloadPCAP():
    if not isLoadedAndReadyToGo() == True:
        redirectToHomePage()
    filelocation = controller.getPCAPLocation()
    return send_file(filelocation, as_attachment=True)

@app.route("/stopeverything")
def shutdownEverything():
    controller.endGracefully()
    return render_template("stopped.html", pagename="Quit")

# Launch everything if just using flashfolder
def standaloneSetUp():
    ####################################
    # Logging
    ####################################
    controller.setupLoggingAndConsole()
    ####################################
    # Kill existing hung processes
    ####################################
    controller.killStuckProcesses()
    ####################################
    # Getting interfaces ready
    ####################################
    controller.prepareInterfaces()
    ####################################
    # Creating Config Files
    ####################################
    controller.createConfigFiles()
    ####################################
    # Setting up IPTables
    ####################################
    controller.setupIPTablesAndRouting()
    ####################################
    # Turning on HostAPD
    ####################################
    controller.enableHOSTAPD()      
    ####################################
    # Turning on DHCPD
    ####################################      
    controller.enableDHCPD()
    ####################################
    # Listen for traffic
    ####################################
    controller.startTShark()    
    
def launchflask(webAppHostAddress, webAppHostPort):    
    app.directory='./'

    #Change the logging level so it doesn't spam the logs
    loglevel = config.getFlaskLoggingLevel()
    log = logging.getLogger('werkzeug')
    log.setLevel(loglevel)
    #app.logger.disabled = True
    #log.disabled = True

    app.run(host=webAppHostAddress, port=webAppHostPort)

    
    
if __name__ == "__main__":
    standaloneSetUp()
    webAppHostAddress = config.getManagementInterfaceGatewayIPAddress()
    webAppHostPort = config.getWebAppPort()    
    launchflask(webAppHostAddress, webAppHostPort)
