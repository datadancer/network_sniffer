#!/usr/bin/python3

# Dylan Todtfeld
# This python script sniffs the network interface or pcap file of your 
# choosing. It alerts you to FIN scans, NULL scans, XMAS scans, 
# usernames/passwords sent in the clear in HTTP and FTP, and to Nikto scans.

# IMPORTANT: This script will not work on Windows! I only got this to work
# with Kali Linux. I don't have a Mac so I don't know about supporting that.
# Will update to support Windows if I have the time.

from scapy.all import *
import pcapy
import argparse
import base64 

#Global variables
incident_count = 1

# Arguments: a packet object
# Returns: boolean
# Purpose: returns true if the FIN flag is on in this packet
# Notes: PASSED
def is_fin_scan(packet):
  if packet[TCP].flags == "F":
    return True
  return False

# Arguments: a packet object
# Returns: boolean
# Purpose: returns true if no flags are on in this packet
# Notes: PASSED
def is_null_scan(packet):
  if packet[TCP].flags == "":
    return True
  return False

# Arguments: a packet object
# Returns: boolean
# Purpose: returns true if the FIN, PUSH, and URG flags are on in this packet
# Notes: PASSED
def is_xmas_scan(packet):
    if packet[TCP].flags == "FPU":
        return True
    return False

# Arguments: packet object
# Returns: boolean
# Purpose: returns true if the packet's destination port is 3389, the port used
#          commonly for Remote Desktop Protocol
def is_rdp(packet):
    if packet[TCP].dport == 3389:
        return True
    return False

# Arguments: packet object
# Returns: boolean
# Purpose: returns true if the packet's destination port is 80, the port
#          used commonly for HTTP
def is_http(packet):
    if packet[TCP].dport == 80:
        return True
    return False

# Arguments: packet object
# Returns: boolean
# Purpose: returns true if the packet's destination port is 21, the port
#          used commonly for FTP
def is_ftp(packet):
    if packet[TCP].dport == 21:
        return True
    return False

# Arguments: packet object
# Returns: boolean
# Purpose: returns true if the packet contains the word "nikto" anywhere in it
def is_nikto(packet):
    nikto_keywords = ["NIKTO", "nikto", "Nikto"]
    for word in nikto_keywords:
        if str(packet[Raw].load).find(word) != -1:
            return True
    return False

# Arguments: packet object
# Returns: Nothing
# Purpose: print the username and password sent over ftp
# NOTE: I can expect the password to immediately follow the username, so I
#       will print the username without the newline
def find_up_ftp(packet):
    global incident_count

    raw_data = str(packet[Raw].load)

    if raw_data.find("USER") != -1:
        list_data = raw_data.split("USER")
        username = str(list_data[1])[:-5] #turns out the \n\r at the end were
                                          #not newline chars, but regular
        print("ALERT " + str(incident_count) + 
              ": Usernames and passwords sent in-the-clear (FTP) (username:" 
              + username, end = '')
    if raw_data.find("PASS") != -1:
        list_data = raw_data.split("PASS")
        password = str(list_data[1])[:-5] #turns out the \n\r at the end were
                                          #not newline chars, but regular
        print(", password:" + password + ")")
        incident_count += 1

# Arguments: packet object
# Returns: nothing
# Purpose: print the username and password sent over HTTP
def find_up_http(packet):
    global incident_count
    raw_data = str(packet[Raw].load)
    if (raw_data.find("Authorization: Basic") != -1): 
        list_data = raw_data.split("Authorization: Basic ")
        up_combo = list_data[1]
        up_combo = str(base64.b64decode(up_combo).decode("utf-8")) 
        up_list = up_combo.split(":")
        print("ALERT " + str(incident_count) + 
              ": Usernames and passwords sent in-the-clear (HTTP) (username:"
               + up_list[0] + ", password:" + up_list[1] + ")")
        incident_count += 1

# Arguments: packet object
# Returns: nothing
# Purpose: prints when a scan has been detected or unencrypted passwords have
#          been sent
def packetcallback(packet):
  try:
    global incident_count

    if is_http(packet):
        find_up_http(packet)
    if is_ftp(packet):
        find_up_ftp(packet)
    
    if is_fin_scan(packet):
        print("ALERT " + str(incident_count) + ": FIN scan is detected from " +
            str(packet[IP].src) + " (TCP)")
        incident_count += 1
    if is_null_scan(packet):
        print("ALERT " + str(incident_count) + ": NULL scan is detected from " +
            str(packet[IP].src) + " (TCP)")
        incident_count += 1
    if is_xmas_scan(packet):
        print("ALERT " + str(incident_count) + ": XMAS scan is detected from " + 
            str(packet[IP].src) + " (TCP)")
        incident_count += 1
    if is_rdp(packet):
        print("ALERT " + str(incident_count) + 
            ": Remote Desktop Protocol scan is detected from " + 
            str(packet[IP].src) + " (RDP)")
        incident_count += 1
    if is_nikto(packet):
        print("ALERT " + str(incident_count) + ": Nikto scan is detected from " +
            str(packet[IP].src) + " (HTTP)")
        incident_count += 1
    
  except:
    pass

# Main part of program
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except pcapy.PcapError:
    print("Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface})
  except:
    print("Sorry, can\'t read network traffic. Are you root?")