######################################################################
# Main - threaded
######################################################################

#############################################################################
#   This script controls the entire project
#############################################################################

import views.flaskWebserver.flask_main as websiteView
import views.console as consoleView

import config as config
import time
import keyboard
import logging
import threading

from rich.console import Console
from rich.progress import Progress
from rich.live import Live
from rich.table import Table

#This is used for creating dummy data for testing, a dummy controller is created
standalonetestmode = config.getIsThisTestMode()
if standalonetestmode == True:
    import test.testcontroller as controller
else:
    import controller as controller

####################################
# Setting up logging and console output
####################################
controller.setupLoggingAndConsole()
log = logging.getLogger("rich")

####################################
# Intro
####################################
console = Console()
richConsoleBannerStyle = config.getRichConsoleBannerStyle()
console.print("######################################################", style=richConsoleBannerStyle, justify="center")
console.print("#      PwnPi IOT Testing Tool", style=richConsoleBannerStyle, justify="center")
console.print("######################################################", style=richConsoleBannerStyle, justify="center")
console.print("Starting Up, please wait", style=richConsoleBannerStyle, justify="center")

#Create a progress bar for the user
with Progress() as LoadingProgressBar:
    loadingProgressTask = LoadingProgressBar.add_task("[red]Loading", total=100)
    
    ####################################
    # Kill existing hung processes
    ####################################
    controller.killStuckProcesses()
    LoadingProgressBar.update(loadingProgressTask, advance=10)

    ####################################
    # Getting interfaces ready
    ####################################
    controller.prepareInterfaces()
    LoadingProgressBar.update(loadingProgressTask, advance=10)    

    ####################################
    # Creating Config Files
    ####################################
    controller.createConfigFiles()
    LoadingProgressBar.update(loadingProgressTask, advance=15)    

    ####################################
    # Setting up IPTables
    ####################################
    controller.setupIPTablesAndRouting()
    LoadingProgressBar.update(loadingProgressTask, advance=5)    

    ####################################
    # Turning on HostAPD
    ####################################
    #Create HOSTAPD output file
    controller.enableHOSTAPD()
    LoadingProgressBar.update(loadingProgressTask, advance=15)      
      
    ####################################
    # Turning on DHCPD
    ####################################      
    controller.enableDHCPD()
    LoadingProgressBar.update(loadingProgressTask, advance=15)        

    ####################################
    # Listen for traffic
    ####################################
    controller.startTShark()
    LoadingProgressBar.update(loadingProgressTask, advance=10)    

#HostAPD/DHCP/TShark are all up and running now, we can tell the user to connect!
log.debug("All services have started and app is ready to use")

######################################################################
# Run and wait
######################################################################
console.print("pIOT is now up and running!", style=richConsoleBannerStyle, justify="center")
if config.getRunConsoleApp() == True:
   consoleView.runConsoleApp()
if config.getRunWebApp() == True:
    webAppHostAddress = config.getManagementInterfaceGatewayIPAddress()
    webAppHostPort = config.getWebAppPort()
    websiteView.launchflask(webAppHostAddress, webAppHostPort)
while True:
    time.sleep(1)
