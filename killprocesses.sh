#!/bin/sh

#Find the Process ID for syncapp running instance

sudo nmcli radio wifi off
sudo rfkill unblock wlan
kill -9 $(ps -ef | grep tshark | grep -v grep | awk '{print $2}')
kill -9 $(ps -ef | grep dhcpd | grep -v grep | awk '{print $2}')
kill -9 $(ps -ef | grep hostapd | grep -v grep | awk '{print $2}')
